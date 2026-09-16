rule TTP_XOR_QUAD_CurrentVersionRun_1ecd {
  strings:
    $key_1ecd = { 4d a2 [2] 69 ac [2] 42 80 [2] 6c a2 [2] 78 b9 [2] 77 a3 [2] 69 be [2] 6b bf [2] 70 b9 [2] 6c be [2] 70 91 }

  condition:
    any of them
}