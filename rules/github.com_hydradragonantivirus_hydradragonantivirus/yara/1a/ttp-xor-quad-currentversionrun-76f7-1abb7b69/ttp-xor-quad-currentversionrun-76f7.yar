rule TTP_XOR_QUAD_CurrentVersionRun_76f7 {
  strings:
    $key_76f7 = { 25 98 [2] 01 96 [2] 2a ba [2] 04 98 [2] 10 83 [2] 1f 99 [2] 01 84 [2] 03 85 [2] 18 83 [2] 04 84 [2] 18 ab }

  condition:
    any of them
}