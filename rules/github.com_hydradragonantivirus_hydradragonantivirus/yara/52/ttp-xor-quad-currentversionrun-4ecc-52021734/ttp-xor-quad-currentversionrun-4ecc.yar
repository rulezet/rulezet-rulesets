rule TTP_XOR_QUAD_CurrentVersionRun_4ecc {
  strings:
    $key_4ecc = { 1d a3 [2] 39 ad [2] 12 81 [2] 3c a3 [2] 28 b8 [2] 27 a2 [2] 39 bf [2] 3b be [2] 20 b8 [2] 3c bf [2] 20 90 }

  condition:
    any of them
}