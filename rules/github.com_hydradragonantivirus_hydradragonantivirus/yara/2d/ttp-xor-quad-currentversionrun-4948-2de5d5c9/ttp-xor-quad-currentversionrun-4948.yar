rule TTP_XOR_QUAD_CurrentVersionRun_4948 {
  strings:
    $key_4948 = { 1a 27 [2] 3e 29 [2] 15 05 [2] 3b 27 [2] 2f 3c [2] 20 26 [2] 3e 3b [2] 3c 3a [2] 27 3c [2] 3b 3b [2] 27 14 }

  condition:
    any of them
}