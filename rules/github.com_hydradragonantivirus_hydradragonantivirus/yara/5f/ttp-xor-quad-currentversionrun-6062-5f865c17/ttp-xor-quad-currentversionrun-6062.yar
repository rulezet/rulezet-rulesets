rule TTP_XOR_QUAD_CurrentVersionRun_6062 {
  strings:
    $key_6062 = { 33 0d [2] 17 03 [2] 3c 2f [2] 12 0d [2] 06 16 [2] 09 0c [2] 17 11 [2] 15 10 [2] 0e 16 [2] 12 11 [2] 0e 3e }

  condition:
    any of them
}