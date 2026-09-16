rule TTP_XOR_QUAD_CurrentVersionRun_5aca {
  strings:
    $key_5aca = { 09 a5 [2] 2d ab [2] 06 87 [2] 28 a5 [2] 3c be [2] 33 a4 [2] 2d b9 [2] 2f b8 [2] 34 be [2] 28 b9 [2] 34 96 }

  condition:
    any of them
}