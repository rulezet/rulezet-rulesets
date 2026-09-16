rule TTP_XOR_QUAD_CurrentVersionRun_e511 {
  strings:
    $key_e511 = { b6 7e [2] 92 70 [2] b9 5c [2] 97 7e [2] 83 65 [2] 8c 7f [2] 92 62 [2] 90 63 [2] 8b 65 [2] 97 62 [2] 8b 4d }

  condition:
    any of them
}