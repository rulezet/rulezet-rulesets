rule TTP_XOR_QUAD_CurrentVersionRun_1bcd {
  strings:
    $key_1bcd = { 48 a2 [2] 6c ac [2] 47 80 [2] 69 a2 [2] 7d b9 [2] 72 a3 [2] 6c be [2] 6e bf [2] 75 b9 [2] 69 be [2] 75 91 }

  condition:
    any of them
}