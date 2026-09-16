rule TTP_XOR_QUAD_CurrentVersionRun_15eb {
  strings:
    $key_15eb = { 46 84 [2] 62 8a [2] 49 a6 [2] 67 84 [2] 73 9f [2] 7c 85 [2] 62 98 [2] 60 99 [2] 7b 9f [2] 67 98 [2] 7b b7 }

  condition:
    any of them
}