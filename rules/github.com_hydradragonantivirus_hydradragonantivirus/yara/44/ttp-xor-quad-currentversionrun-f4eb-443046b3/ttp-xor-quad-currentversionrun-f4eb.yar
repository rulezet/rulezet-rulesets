rule TTP_XOR_QUAD_CurrentVersionRun_f4eb {
  strings:
    $key_f4eb = { a7 84 [2] 83 8a [2] a8 a6 [2] 86 84 [2] 92 9f [2] 9d 85 [2] 83 98 [2] 81 99 [2] 9a 9f [2] 86 98 [2] 9a b7 }

  condition:
    any of them
}