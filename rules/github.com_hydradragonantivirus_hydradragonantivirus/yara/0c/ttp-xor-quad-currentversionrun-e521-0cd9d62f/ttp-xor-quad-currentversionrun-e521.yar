rule TTP_XOR_QUAD_CurrentVersionRun_e521 {
  strings:
    $key_e521 = { b6 4e [2] 92 40 [2] b9 6c [2] 97 4e [2] 83 55 [2] 8c 4f [2] 92 52 [2] 90 53 [2] 8b 55 [2] 97 52 [2] 8b 7d }

  condition:
    any of them
}