rule TTP_XOR_QUAD_CurrentVersionRun_6177 {
  strings:
    $key_6177 = { 32 18 [2] 16 16 [2] 3d 3a [2] 13 18 [2] 07 03 [2] 08 19 [2] 16 04 [2] 14 05 [2] 0f 03 [2] 13 04 [2] 0f 2b }

  condition:
    any of them
}