rule TTP_XOR_QUAD_CurrentVersionRun_7d5f {
  strings:
    $key_7d5f = { 2e 30 [2] 0a 3e [2] 21 12 [2] 0f 30 [2] 1b 2b [2] 14 31 [2] 0a 2c [2] 08 2d [2] 13 2b [2] 0f 2c [2] 13 03 }

  condition:
    any of them
}