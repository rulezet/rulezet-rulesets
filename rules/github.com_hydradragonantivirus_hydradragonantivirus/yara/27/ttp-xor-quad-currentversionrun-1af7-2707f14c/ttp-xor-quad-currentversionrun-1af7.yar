rule TTP_XOR_QUAD_CurrentVersionRun_1af7 {
  strings:
    $key_1af7 = { 49 98 [2] 6d 96 [2] 46 ba [2] 68 98 [2] 7c 83 [2] 73 99 [2] 6d 84 [2] 6f 85 [2] 74 83 [2] 68 84 [2] 74 ab }

  condition:
    any of them
}