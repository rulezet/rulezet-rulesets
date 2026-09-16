rule TTP_XOR_QUAD_CurrentVersionRun_2ccd {
  strings:
    $key_2ccd = { 7f a2 [2] 5b ac [2] 70 80 [2] 5e a2 [2] 4a b9 [2] 45 a3 [2] 5b be [2] 59 bf [2] 42 b9 [2] 5e be [2] 42 91 }

  condition:
    any of them
}