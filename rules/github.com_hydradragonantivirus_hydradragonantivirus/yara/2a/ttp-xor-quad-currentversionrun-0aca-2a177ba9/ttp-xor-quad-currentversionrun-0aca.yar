rule TTP_XOR_QUAD_CurrentVersionRun_0aca {
  strings:
    $key_0aca = { 59 a5 [2] 7d ab [2] 56 87 [2] 78 a5 [2] 6c be [2] 63 a4 [2] 7d b9 [2] 7f b8 [2] 64 be [2] 78 b9 [2] 64 96 }

  condition:
    any of them
}