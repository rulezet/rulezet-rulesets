rule TTP_XOR_QUAD_CurrentVersionRun_0c35 {
  strings:
    $key_0c35 = { 5f 5a [2] 7b 54 [2] 50 78 [2] 7e 5a [2] 6a 41 [2] 65 5b [2] 7b 46 [2] 79 47 [2] 62 41 [2] 7e 46 [2] 62 69 }

  condition:
    any of them
}