rule TTP_XOR_QUAD_CurrentVersionRun_6ef7 {
  strings:
    $key_6ef7 = { 3d 98 [2] 19 96 [2] 32 ba [2] 1c 98 [2] 08 83 [2] 07 99 [2] 19 84 [2] 1b 85 [2] 00 83 [2] 1c 84 [2] 00 ab }

  condition:
    any of them
}