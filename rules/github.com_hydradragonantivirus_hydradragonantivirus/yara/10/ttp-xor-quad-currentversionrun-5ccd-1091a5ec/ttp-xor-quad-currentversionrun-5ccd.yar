rule TTP_XOR_QUAD_CurrentVersionRun_5ccd {
  strings:
    $key_5ccd = { 0f a2 [2] 2b ac [2] 00 80 [2] 2e a2 [2] 3a b9 [2] 35 a3 [2] 2b be [2] 29 bf [2] 32 b9 [2] 2e be [2] 32 91 }

  condition:
    any of them
}