rule TTP_XOR_QUAD_CurrentVersionRun_31eb {
  strings:
    $key_31eb = { 62 84 [2] 46 8a [2] 6d a6 [2] 43 84 [2] 57 9f [2] 58 85 [2] 46 98 [2] 44 99 [2] 5f 9f [2] 43 98 [2] 5f b7 }

  condition:
    any of them
}