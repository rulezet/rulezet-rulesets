rule TTP_XOR_QUAD_CurrentVersionRun_4ff7 {
  strings:
    $key_4ff7 = { 1c 98 [2] 38 96 [2] 13 ba [2] 3d 98 [2] 29 83 [2] 26 99 [2] 38 84 [2] 3a 85 [2] 21 83 [2] 3d 84 [2] 21 ab }

  condition:
    any of them
}