rule TTP_XOR_QUAD_CurrentVersionRun_7feb {
  strings:
    $key_7feb = { 2c 84 [2] 08 8a [2] 23 a6 [2] 0d 84 [2] 19 9f [2] 16 85 [2] 08 98 [2] 0a 99 [2] 11 9f [2] 0d 98 [2] 11 b7 }

  condition:
    any of them
}