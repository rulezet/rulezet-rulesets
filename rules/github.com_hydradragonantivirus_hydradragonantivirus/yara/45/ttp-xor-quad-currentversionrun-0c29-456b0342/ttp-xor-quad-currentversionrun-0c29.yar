rule TTP_XOR_QUAD_CurrentVersionRun_0c29 {
  strings:
    $key_0c29 = { 5f 46 [2] 7b 48 [2] 50 64 [2] 7e 46 [2] 6a 5d [2] 65 47 [2] 7b 5a [2] 79 5b [2] 62 5d [2] 7e 5a [2] 62 75 }

  condition:
    any of them
}