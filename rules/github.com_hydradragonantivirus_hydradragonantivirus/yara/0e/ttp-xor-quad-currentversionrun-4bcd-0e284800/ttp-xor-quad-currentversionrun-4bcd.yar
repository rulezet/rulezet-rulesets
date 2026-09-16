rule TTP_XOR_QUAD_CurrentVersionRun_4bcd {
  strings:
    $key_4bcd = { 18 a2 [2] 3c ac [2] 17 80 [2] 39 a2 [2] 2d b9 [2] 22 a3 [2] 3c be [2] 3e bf [2] 25 b9 [2] 39 be [2] 25 91 }

  condition:
    any of them
}