rule TTP_XOR_QUAD_CurrentVersionRun_6117 {
  strings:
    $key_6117 = { 32 78 [2] 16 76 [2] 3d 5a [2] 13 78 [2] 07 63 [2] 08 79 [2] 16 64 [2] 14 65 [2] 0f 63 [2] 13 64 [2] 0f 4b }

  condition:
    any of them
}