rule TTP_XOR_QUAD_CurrentVersionRun_06f7 {
  strings:
    $key_06f7 = { 55 98 [2] 71 96 [2] 5a ba [2] 74 98 [2] 60 83 [2] 6f 99 [2] 71 84 [2] 73 85 [2] 68 83 [2] 74 84 [2] 68 ab }

  condition:
    any of them
}