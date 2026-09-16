rule TTP_XOR_QUAD_CurrentVersionRun_61f4 {
  strings:
    $key_61f4 = { 32 9b [2] 16 95 [2] 3d b9 [2] 13 9b [2] 07 80 [2] 08 9a [2] 16 87 [2] 14 86 [2] 0f 80 [2] 13 87 [2] 0f a8 }

  condition:
    any of them
}