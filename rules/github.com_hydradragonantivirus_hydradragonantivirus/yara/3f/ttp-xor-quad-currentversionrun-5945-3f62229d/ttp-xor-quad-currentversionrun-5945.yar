rule TTP_XOR_QUAD_CurrentVersionRun_5945 {
  strings:
    $key_5945 = { 0a 2a [2] 2e 24 [2] 05 08 [2] 2b 2a [2] 3f 31 [2] 30 2b [2] 2e 36 [2] 2c 37 [2] 37 31 [2] 2b 36 [2] 37 19 }

  condition:
    any of them
}