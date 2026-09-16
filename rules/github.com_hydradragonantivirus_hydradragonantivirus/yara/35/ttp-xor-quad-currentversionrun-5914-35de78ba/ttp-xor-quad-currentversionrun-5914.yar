rule TTP_XOR_QUAD_CurrentVersionRun_5914 {
  strings:
    $key_5914 = { 0a 7b [2] 2e 75 [2] 05 59 [2] 2b 7b [2] 3f 60 [2] 30 7a [2] 2e 67 [2] 2c 66 [2] 37 60 [2] 2b 67 [2] 37 48 }

  condition:
    any of them
}