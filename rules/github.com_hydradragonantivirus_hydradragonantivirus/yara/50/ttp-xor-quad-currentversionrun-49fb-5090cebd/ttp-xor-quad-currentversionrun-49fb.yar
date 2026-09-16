rule TTP_XOR_QUAD_CurrentVersionRun_49fb {
  strings:
    $key_49fb = { 1a 94 [2] 3e 9a [2] 15 b6 [2] 3b 94 [2] 2f 8f [2] 20 95 [2] 3e 88 [2] 3c 89 [2] 27 8f [2] 3b 88 [2] 27 a7 }

  condition:
    any of them
}