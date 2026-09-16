rule TTP_XOR_QUAD_CurrentVersionRun_1ccd {
  strings:
    $key_1ccd = { 4f a2 [2] 6b ac [2] 40 80 [2] 6e a2 [2] 7a b9 [2] 75 a3 [2] 6b be [2] 69 bf [2] 72 b9 [2] 6e be [2] 72 91 }

  condition:
    any of them
}