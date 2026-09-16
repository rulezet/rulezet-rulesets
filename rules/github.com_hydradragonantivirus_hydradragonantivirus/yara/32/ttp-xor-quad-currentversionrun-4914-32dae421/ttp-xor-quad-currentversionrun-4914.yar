rule TTP_XOR_QUAD_CurrentVersionRun_4914 {
  strings:
    $key_4914 = { 1a 7b [2] 3e 75 [2] 15 59 [2] 3b 7b [2] 2f 60 [2] 20 7a [2] 3e 67 [2] 3c 66 [2] 27 60 [2] 3b 67 [2] 27 48 }

  condition:
    any of them
}