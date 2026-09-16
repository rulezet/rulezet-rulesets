rule TTP_XOR_QUAD_CurrentVersionRun_2bcd {
  strings:
    $key_2bcd = { 78 a2 [2] 5c ac [2] 77 80 [2] 59 a2 [2] 4d b9 [2] 42 a3 [2] 5c be [2] 5e bf [2] 45 b9 [2] 59 be [2] 45 91 }

  condition:
    any of them
}