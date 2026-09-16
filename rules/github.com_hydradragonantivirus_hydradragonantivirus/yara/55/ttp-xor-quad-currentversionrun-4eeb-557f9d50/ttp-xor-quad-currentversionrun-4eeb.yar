rule TTP_XOR_QUAD_CurrentVersionRun_4eeb {
  strings:
    $key_4eeb = { 1d 84 [2] 39 8a [2] 12 a6 [2] 3c 84 [2] 28 9f [2] 27 85 [2] 39 98 [2] 3b 99 [2] 20 9f [2] 3c 98 [2] 20 b7 }

  condition:
    any of them
}