rule TTP_XOR_QUAD_CurrentVersionRun_53f7 {
  strings:
    $key_53f7 = { 00 98 [2] 24 96 [2] 0f ba [2] 21 98 [2] 35 83 [2] 3a 99 [2] 24 84 [2] 26 85 [2] 3d 83 [2] 21 84 [2] 3d ab }

  condition:
    any of them
}