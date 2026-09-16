rule TTP_XOR_QUAD_CurrentVersionRun_59eb {
  strings:
    $key_59eb = { 0a 84 [2] 2e 8a [2] 05 a6 [2] 2b 84 [2] 3f 9f [2] 30 85 [2] 2e 98 [2] 2c 99 [2] 37 9f [2] 2b 98 [2] 37 b7 }

  condition:
    any of them
}