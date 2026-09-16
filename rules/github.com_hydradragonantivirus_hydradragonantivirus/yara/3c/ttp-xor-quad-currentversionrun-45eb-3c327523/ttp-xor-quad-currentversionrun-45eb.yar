rule TTP_XOR_QUAD_CurrentVersionRun_45eb {
  strings:
    $key_45eb = { 16 84 [2] 32 8a [2] 19 a6 [2] 37 84 [2] 23 9f [2] 2c 85 [2] 32 98 [2] 30 99 [2] 2b 9f [2] 37 98 [2] 2b b7 }

  condition:
    any of them
}