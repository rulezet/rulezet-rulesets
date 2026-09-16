rule TTP_XOR_QUAD_CurrentVersionRun_65eb {
  strings:
    $key_65eb = { 36 84 [2] 12 8a [2] 39 a6 [2] 17 84 [2] 03 9f [2] 0c 85 [2] 12 98 [2] 10 99 [2] 0b 9f [2] 17 98 [2] 0b b7 }

  condition:
    any of them
}