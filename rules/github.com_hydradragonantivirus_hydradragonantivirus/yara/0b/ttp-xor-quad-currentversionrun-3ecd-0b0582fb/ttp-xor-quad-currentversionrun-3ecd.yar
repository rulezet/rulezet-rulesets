rule TTP_XOR_QUAD_CurrentVersionRun_3ecd {
  strings:
    $key_3ecd = { 6d a2 [2] 49 ac [2] 62 80 [2] 4c a2 [2] 58 b9 [2] 57 a3 [2] 49 be [2] 4b bf [2] 50 b9 [2] 4c be [2] 50 91 }

  condition:
    any of them
}