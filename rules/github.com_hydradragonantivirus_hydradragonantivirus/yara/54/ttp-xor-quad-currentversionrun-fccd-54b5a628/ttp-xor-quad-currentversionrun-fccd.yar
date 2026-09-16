rule TTP_XOR_QUAD_CurrentVersionRun_fccd {
  strings:
    $key_fccd = { af a2 [2] 8b ac [2] a0 80 [2] 8e a2 [2] 9a b9 [2] 95 a3 [2] 8b be [2] 89 bf [2] 92 b9 [2] 8e be [2] 92 91 }

  condition:
    any of them
}