rule TTP_XOR_QUAD_CurrentVersionRun_1aca {
  strings:
    $key_1aca = { 49 a5 [2] 6d ab [2] 46 87 [2] 68 a5 [2] 7c be [2] 73 a4 [2] 6d b9 [2] 6f b8 [2] 74 be [2] 68 b9 [2] 74 96 }

  condition:
    any of them
}