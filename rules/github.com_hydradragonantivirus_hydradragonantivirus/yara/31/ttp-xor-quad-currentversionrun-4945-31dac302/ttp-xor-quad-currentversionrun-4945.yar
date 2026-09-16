rule TTP_XOR_QUAD_CurrentVersionRun_4945 {
  strings:
    $key_4945 = { 1a 2a [2] 3e 24 [2] 15 08 [2] 3b 2a [2] 2f 31 [2] 20 2b [2] 3e 36 [2] 3c 37 [2] 27 31 [2] 3b 36 [2] 27 19 }

  condition:
    any of them
}