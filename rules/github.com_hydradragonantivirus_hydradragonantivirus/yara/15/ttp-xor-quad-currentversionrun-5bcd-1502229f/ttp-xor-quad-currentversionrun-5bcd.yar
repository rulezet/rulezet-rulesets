rule TTP_XOR_QUAD_CurrentVersionRun_5bcd {
  strings:
    $key_5bcd = { 08 a2 [2] 2c ac [2] 07 80 [2] 29 a2 [2] 3d b9 [2] 32 a3 [2] 2c be [2] 2e bf [2] 35 b9 [2] 29 be [2] 35 91 }

  condition:
    any of them
}