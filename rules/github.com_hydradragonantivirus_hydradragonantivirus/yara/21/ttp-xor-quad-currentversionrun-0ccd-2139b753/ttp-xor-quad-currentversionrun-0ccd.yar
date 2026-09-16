rule TTP_XOR_QUAD_CurrentVersionRun_0ccd {
  strings:
    $key_0ccd = { 5f a2 [2] 7b ac [2] 50 80 [2] 7e a2 [2] 6a b9 [2] 65 a3 [2] 7b be [2] 79 bf [2] 62 b9 [2] 7e be [2] 62 91 }

  condition:
    any of them
}