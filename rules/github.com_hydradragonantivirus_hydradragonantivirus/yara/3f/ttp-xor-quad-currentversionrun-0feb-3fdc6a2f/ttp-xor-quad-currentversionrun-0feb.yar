rule TTP_XOR_QUAD_CurrentVersionRun_0feb {
  strings:
    $key_0feb = { 5c 84 [2] 78 8a [2] 53 a6 [2] 7d 84 [2] 69 9f [2] 66 85 [2] 78 98 [2] 7a 99 [2] 61 9f [2] 7d 98 [2] 61 b7 }

  condition:
    any of them
}