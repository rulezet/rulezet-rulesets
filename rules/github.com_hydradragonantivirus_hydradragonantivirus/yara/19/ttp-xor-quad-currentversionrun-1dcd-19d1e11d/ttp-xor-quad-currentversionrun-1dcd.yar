rule TTP_XOR_QUAD_CurrentVersionRun_1dcd {
  strings:
    $key_1dcd = { 4e a2 [2] 6a ac [2] 41 80 [2] 6f a2 [2] 7b b9 [2] 74 a3 [2] 6a be [2] 68 bf [2] 73 b9 [2] 6f be [2] 73 91 }

  condition:
    any of them
}