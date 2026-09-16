rule TTP_XOR_QUAD_CurrentVersionRun_2a02 {
  strings:
    $key_2a02 = { 79 6d [2] 5d 63 [2] 76 4f [2] 58 6d [2] 4c 76 [2] 43 6c [2] 5d 71 [2] 5f 70 [2] 44 76 [2] 58 71 [2] 44 5e }

  condition:
    any of them
}