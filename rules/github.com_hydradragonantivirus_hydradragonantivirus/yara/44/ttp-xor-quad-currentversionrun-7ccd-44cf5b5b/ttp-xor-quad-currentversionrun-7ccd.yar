rule TTP_XOR_QUAD_CurrentVersionRun_7ccd {
  strings:
    $key_7ccd = { 2f a2 [2] 0b ac [2] 20 80 [2] 0e a2 [2] 1a b9 [2] 15 a3 [2] 0b be [2] 09 bf [2] 12 b9 [2] 0e be [2] 12 91 }

  condition:
    any of them
}