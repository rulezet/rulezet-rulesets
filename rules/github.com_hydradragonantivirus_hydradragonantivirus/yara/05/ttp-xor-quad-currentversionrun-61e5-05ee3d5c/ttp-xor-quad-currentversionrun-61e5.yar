rule TTP_XOR_QUAD_CurrentVersionRun_61e5 {
  strings:
    $key_61e5 = { 32 8a [2] 16 84 [2] 3d a8 [2] 13 8a [2] 07 91 [2] 08 8b [2] 16 96 [2] 14 97 [2] 0f 91 [2] 13 96 [2] 0f b9 }

  condition:
    any of them
}