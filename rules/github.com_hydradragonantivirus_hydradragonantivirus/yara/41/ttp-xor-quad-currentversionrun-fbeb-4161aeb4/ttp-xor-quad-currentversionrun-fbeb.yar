rule TTP_XOR_QUAD_CurrentVersionRun_fbeb {
  strings:
    $key_fbeb = { a8 84 [2] 8c 8a [2] a7 a6 [2] 89 84 [2] 9d 9f [2] 92 85 [2] 8c 98 [2] 8e 99 [2] 95 9f [2] 89 98 [2] 95 b7 }

  condition:
    any of them
}