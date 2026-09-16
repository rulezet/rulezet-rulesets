rule TTP_XOR_QUAD_CurrentVersionRun_63eb {
  strings:
    $key_63eb = { 30 84 [2] 14 8a [2] 3f a6 [2] 11 84 [2] 05 9f [2] 0a 85 [2] 14 98 [2] 16 99 [2] 0d 9f [2] 11 98 [2] 0d b7 }

  condition:
    any of them
}