rule TTP_XOR_QUAD_CurrentVersionRun_17f7 {
  strings:
    $key_17f7 = { 44 98 [2] 60 96 [2] 4b ba [2] 65 98 [2] 71 83 [2] 7e 99 [2] 60 84 [2] 62 85 [2] 79 83 [2] 65 84 [2] 79 ab }

  condition:
    any of them
}