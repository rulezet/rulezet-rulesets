rule TTP_XOR_QUAD_CurrentVersionRun_edcd {
  strings:
    $key_edcd = { be a2 [2] 9a ac [2] b1 80 [2] 9f a2 [2] 8b b9 [2] 84 a3 [2] 9a be [2] 98 bf [2] 83 b9 [2] 9f be [2] 83 91 }

  condition:
    any of them
}