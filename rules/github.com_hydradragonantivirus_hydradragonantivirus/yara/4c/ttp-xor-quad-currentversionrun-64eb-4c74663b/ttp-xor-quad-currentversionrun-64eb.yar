rule TTP_XOR_QUAD_CurrentVersionRun_64eb {
  strings:
    $key_64eb = { 37 84 [2] 13 8a [2] 38 a6 [2] 16 84 [2] 02 9f [2] 0d 85 [2] 13 98 [2] 11 99 [2] 0a 9f [2] 16 98 [2] 0a b7 }

  condition:
    any of them
}