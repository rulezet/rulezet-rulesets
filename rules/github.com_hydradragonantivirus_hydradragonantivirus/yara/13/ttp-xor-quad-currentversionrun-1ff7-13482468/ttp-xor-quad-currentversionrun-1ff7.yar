rule TTP_XOR_QUAD_CurrentVersionRun_1ff7 {
  strings:
    $key_1ff7 = { 4c 98 [2] 68 96 [2] 43 ba [2] 6d 98 [2] 79 83 [2] 76 99 [2] 68 84 [2] 6a 85 [2] 71 83 [2] 6d 84 [2] 71 ab }

  condition:
    any of them
}