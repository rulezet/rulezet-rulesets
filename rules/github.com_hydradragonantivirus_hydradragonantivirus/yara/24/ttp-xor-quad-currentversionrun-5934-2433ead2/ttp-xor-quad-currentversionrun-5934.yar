rule TTP_XOR_QUAD_CurrentVersionRun_5934 {
  strings:
    $key_5934 = { 0a 5b [2] 2e 55 [2] 05 79 [2] 2b 5b [2] 3f 40 [2] 30 5a [2] 2e 47 [2] 2c 46 [2] 37 40 [2] 2b 47 [2] 37 68 }

  condition:
    any of them
}