rule TTP_XOR_QUAD_CurrentVersionRun_5ecc {
  strings:
    $key_5ecc = { 0d a3 [2] 29 ad [2] 02 81 [2] 2c a3 [2] 38 b8 [2] 37 a2 [2] 29 bf [2] 2b be [2] 30 b8 [2] 2c bf [2] 30 90 }

  condition:
    any of them
}