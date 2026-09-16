rule TTP_XOR_QUAD_CurrentVersionRun_45d0 {
  strings:
    $key_45d0 = { 16 bf [2] 32 b1 [2] 19 9d [2] 37 bf [2] 23 a4 [2] 2c be [2] 32 a3 [2] 30 a2 [2] 2b a4 [2] 37 a3 [2] 2b 8c }

  condition:
    any of them
}