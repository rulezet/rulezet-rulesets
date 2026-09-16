rule TTP_XOR_QUAD_CurrentVersionRun_0ecd {
  strings:
    $key_0ecd = { 5d a2 [2] 79 ac [2] 52 80 [2] 7c a2 [2] 68 b9 [2] 67 a3 [2] 79 be [2] 7b bf [2] 60 b9 [2] 7c be [2] 60 91 }

  condition:
    any of them
}