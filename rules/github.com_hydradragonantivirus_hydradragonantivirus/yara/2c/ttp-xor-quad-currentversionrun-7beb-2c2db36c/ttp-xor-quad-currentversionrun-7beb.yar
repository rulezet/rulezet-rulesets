rule TTP_XOR_QUAD_CurrentVersionRun_7beb {
  strings:
    $key_7beb = { 28 84 [2] 0c 8a [2] 27 a6 [2] 09 84 [2] 1d 9f [2] 12 85 [2] 0c 98 [2] 0e 99 [2] 15 9f [2] 09 98 [2] 15 b7 }

  condition:
    any of them
}