rule TTP_XOR_QUAD_CurrentVersionRun_6116 {
  strings:
    $key_6116 = { 32 79 [2] 16 77 [2] 3d 5b [2] 13 79 [2] 07 62 [2] 08 78 [2] 16 65 [2] 14 64 [2] 0f 62 [2] 13 65 [2] 0f 4a }

  condition:
    any of them
}