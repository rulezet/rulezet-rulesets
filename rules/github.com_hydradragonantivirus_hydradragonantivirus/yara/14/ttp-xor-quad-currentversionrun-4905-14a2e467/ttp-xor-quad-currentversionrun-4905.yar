rule TTP_XOR_QUAD_CurrentVersionRun_4905 {
  strings:
    $key_4905 = { 1a 6a [2] 3e 64 [2] 15 48 [2] 3b 6a [2] 2f 71 [2] 20 6b [2] 3e 76 [2] 3c 77 [2] 27 71 [2] 3b 76 [2] 27 59 }

  condition:
    any of them
}