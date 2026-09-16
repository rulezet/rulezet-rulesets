rule TTP_XOR_QUAD_CurrentVersionRun_16f7 {
  strings:
    $key_16f7 = { 45 98 [2] 61 96 [2] 4a ba [2] 64 98 [2] 70 83 [2] 7f 99 [2] 61 84 [2] 63 85 [2] 78 83 [2] 64 84 [2] 78 ab }

  condition:
    any of them
}