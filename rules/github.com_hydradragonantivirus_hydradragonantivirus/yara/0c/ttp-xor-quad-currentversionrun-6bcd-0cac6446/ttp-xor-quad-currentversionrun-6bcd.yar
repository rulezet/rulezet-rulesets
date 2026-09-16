rule TTP_XOR_QUAD_CurrentVersionRun_6bcd {
  strings:
    $key_6bcd = { 38 a2 [2] 1c ac [2] 37 80 [2] 19 a2 [2] 0d b9 [2] 02 a3 [2] 1c be [2] 1e bf [2] 05 b9 [2] 19 be [2] 05 91 }

  condition:
    any of them
}