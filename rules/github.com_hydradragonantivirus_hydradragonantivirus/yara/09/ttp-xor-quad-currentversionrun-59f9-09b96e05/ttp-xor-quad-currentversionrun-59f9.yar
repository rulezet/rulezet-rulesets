rule TTP_XOR_QUAD_CurrentVersionRun_59f9 {
  strings:
    $key_59f9 = { 0a 96 [2] 2e 98 [2] 05 b4 [2] 2b 96 [2] 3f 8d [2] 30 97 [2] 2e 8a [2] 2c 8b [2] 37 8d [2] 2b 8a [2] 37 a5 }

  condition:
    any of them
}