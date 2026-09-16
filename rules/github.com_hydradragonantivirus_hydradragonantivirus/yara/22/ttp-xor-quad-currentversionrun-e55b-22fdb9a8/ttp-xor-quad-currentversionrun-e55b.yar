rule TTP_XOR_QUAD_CurrentVersionRun_e55b {
  strings:
    $key_e55b = { b6 34 [2] 92 3a [2] b9 16 [2] 97 34 [2] 83 2f [2] 8c 35 [2] 92 28 [2] 90 29 [2] 8b 2f [2] 97 28 [2] 8b 07 }

  condition:
    any of them
}