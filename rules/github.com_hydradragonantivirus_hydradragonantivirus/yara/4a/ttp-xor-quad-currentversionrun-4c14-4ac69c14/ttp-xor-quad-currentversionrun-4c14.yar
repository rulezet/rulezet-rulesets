rule TTP_XOR_QUAD_CurrentVersionRun_4c14 {
  strings:
    $key_4c14 = { 1f 7b [2] 3b 75 [2] 10 59 [2] 3e 7b [2] 2a 60 [2] 25 7a [2] 3b 67 [2] 39 66 [2] 22 60 [2] 3e 67 [2] 22 48 }

  condition:
    any of them
}