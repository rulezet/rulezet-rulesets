rule TTP_XOR_QUAD_CurrentVersionRun_5dcd {
  strings:
    $key_5dcd = { 0e a2 [2] 2a ac [2] 01 80 [2] 2f a2 [2] 3b b9 [2] 34 a3 [2] 2a be [2] 28 bf [2] 33 b9 [2] 2f be [2] 33 91 }

  condition:
    any of them
}