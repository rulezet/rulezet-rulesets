rule TTP_XOR_QUAD_CurrentVersionRun_59ea {
  strings:
    $key_59ea = { 0a 85 [2] 2e 8b [2] 05 a7 [2] 2b 85 [2] 3f 9e [2] 30 84 [2] 2e 99 [2] 2c 98 [2] 37 9e [2] 2b 99 [2] 37 b6 }

  condition:
    any of them
}