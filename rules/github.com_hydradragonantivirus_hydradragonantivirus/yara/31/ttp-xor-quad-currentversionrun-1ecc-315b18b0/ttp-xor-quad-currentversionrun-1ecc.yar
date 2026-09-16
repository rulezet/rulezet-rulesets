rule TTP_XOR_QUAD_CurrentVersionRun_1ecc {
  strings:
    $key_1ecc = { 4d a3 [2] 69 ad [2] 42 81 [2] 6c a3 [2] 78 b8 [2] 77 a2 [2] 69 bf [2] 6b be [2] 70 b8 [2] 6c bf [2] 70 90 }

  condition:
    any of them
}