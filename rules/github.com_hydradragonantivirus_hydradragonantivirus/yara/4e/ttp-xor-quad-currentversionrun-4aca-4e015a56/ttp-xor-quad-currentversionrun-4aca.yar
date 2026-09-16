rule TTP_XOR_QUAD_CurrentVersionRun_4aca {
  strings:
    $key_4aca = { 19 a5 [2] 3d ab [2] 16 87 [2] 38 a5 [2] 2c be [2] 23 a4 [2] 3d b9 [2] 3f b8 [2] 24 be [2] 38 b9 [2] 24 96 }

  condition:
    any of them
}