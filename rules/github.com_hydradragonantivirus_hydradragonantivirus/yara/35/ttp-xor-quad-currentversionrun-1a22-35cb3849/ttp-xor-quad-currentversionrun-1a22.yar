rule TTP_XOR_QUAD_CurrentVersionRun_1a22 {
  strings:
    $key_1a22 = { 49 4d [2] 6d 43 [2] 46 6f [2] 68 4d [2] 7c 56 [2] 73 4c [2] 6d 51 [2] 6f 50 [2] 74 56 [2] 68 51 [2] 74 7e }

  condition:
    any of them
}