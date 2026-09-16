rule TTP_XOR_QUAD_CurrentVersionRun_efeb {
  strings:
    $key_efeb = { bc 84 [2] 98 8a [2] b3 a6 [2] 9d 84 [2] 89 9f [2] 86 85 [2] 98 98 [2] 9a 99 [2] 81 9f [2] 9d 98 [2] 81 b7 }

  condition:
    any of them
}