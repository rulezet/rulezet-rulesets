rule TTP_XOR_QUAD_CurrentVersionRun_1f22 {
  strings:
    $key_1f22 = { 4c 4d [2] 68 43 [2] 43 6f [2] 6d 4d [2] 79 56 [2] 76 4c [2] 68 51 [2] 6a 50 [2] 71 56 [2] 6d 51 [2] 71 7e }

  condition:
    any of them
}