rule TTP_XOR_QUAD_CurrentVersionRun_71f7 {
  strings:
    $key_71f7 = { 22 98 [2] 06 96 [2] 2d ba [2] 03 98 [2] 17 83 [2] 18 99 [2] 06 84 [2] 04 85 [2] 1f 83 [2] 03 84 [2] 1f ab }

  condition:
    any of them
}