rule TTP_XOR_QUAD_CurrentVersionRun_6762 {
  strings:
    $key_6762 = { 34 0d [2] 10 03 [2] 3b 2f [2] 15 0d [2] 01 16 [2] 0e 0c [2] 10 11 [2] 12 10 [2] 09 16 [2] 15 11 [2] 09 3e }

  condition:
    any of them
}