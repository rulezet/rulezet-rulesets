rule TTP_XOR_QUAD_CurrentVersionRun_fbcd {
  strings:
    $key_fbcd = { a8 a2 [2] 8c ac [2] a7 80 [2] 89 a2 [2] 9d b9 [2] 92 a3 [2] 8c be [2] 8e bf [2] 95 b9 [2] 89 be [2] 95 91 }

  condition:
    any of them
}