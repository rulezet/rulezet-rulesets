rule TTP_XOR_QUAD_CurrentVersionRun_e762 {
  strings:
    $key_e762 = { b4 0d [2] 90 03 [2] bb 2f [2] 95 0d [2] 81 16 [2] 8e 0c [2] 90 11 [2] 92 10 [2] 89 16 [2] 95 11 [2] 89 3e }

  condition:
    any of them
}