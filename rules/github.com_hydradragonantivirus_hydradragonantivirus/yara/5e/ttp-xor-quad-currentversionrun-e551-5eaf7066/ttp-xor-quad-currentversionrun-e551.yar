rule TTP_XOR_QUAD_CurrentVersionRun_e551 {
  strings:
    $key_e551 = { b6 3e [2] 92 30 [2] b9 1c [2] 97 3e [2] 83 25 [2] 8c 3f [2] 92 22 [2] 90 23 [2] 8b 25 [2] 97 22 [2] 8b 0d }

  condition:
    any of them
}