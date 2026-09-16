rule TTP_XOR_QUAD_CurrentVersionRun_62fb {
  strings:
    $key_62fb = { 31 94 [2] 15 9a [2] 3e b6 [2] 10 94 [2] 04 8f [2] 0b 95 [2] 15 88 [2] 17 89 [2] 0c 8f [2] 10 88 [2] 0c a7 }

  condition:
    any of them
}