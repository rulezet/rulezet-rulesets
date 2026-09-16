rule TTP_XOR_QUAD_CurrentVersionRun_1f62 {
  strings:
    $key_1f62 = { 4c 0d [2] 68 03 [2] 43 2f [2] 6d 0d [2] 79 16 [2] 76 0c [2] 68 11 [2] 6a 10 [2] 71 16 [2] 6d 11 [2] 71 3e }

  condition:
    any of them
}