rule TTP_XOR_QUAD_CurrentVersionRun_6919 {
  strings:
    $key_6919 = { 3a 76 [2] 1e 78 [2] 35 54 [2] 1b 76 [2] 0f 6d [2] 00 77 [2] 1e 6a [2] 1c 6b [2] 07 6d [2] 1b 6a [2] 07 45 }

  condition:
    any of them
}