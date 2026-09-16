rule TTP_XOR_QUAD_CurrentVersionRun_610b {
  strings:
    $key_610b = { 32 64 [2] 16 6a [2] 3d 46 [2] 13 64 [2] 07 7f [2] 08 65 [2] 16 78 [2] 14 79 [2] 0f 7f [2] 13 78 [2] 0f 57 }

  condition:
    any of them
}