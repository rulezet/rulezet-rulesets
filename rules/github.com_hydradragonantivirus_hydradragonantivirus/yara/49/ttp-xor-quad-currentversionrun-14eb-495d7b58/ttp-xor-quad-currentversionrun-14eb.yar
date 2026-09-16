rule TTP_XOR_QUAD_CurrentVersionRun_14eb {
  strings:
    $key_14eb = { 47 84 [2] 63 8a [2] 48 a6 [2] 66 84 [2] 72 9f [2] 7d 85 [2] 63 98 [2] 61 99 [2] 7a 9f [2] 66 98 [2] 7a b7 }

  condition:
    any of them
}