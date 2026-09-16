rule TTP_XOR_QUAD_CurrentVersionRun_6aca {
  strings:
    $key_6aca = { 39 a5 [2] 1d ab [2] 36 87 [2] 18 a5 [2] 0c be [2] 03 a4 [2] 1d b9 [2] 1f b8 [2] 04 be [2] 18 b9 [2] 04 96 }

  condition:
    any of them
}