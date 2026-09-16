rule TTP_XOR_QUAD_CurrentVersionRun_6924 {
  strings:
    $key_6924 = { 3a 4b [2] 1e 45 [2] 35 69 [2] 1b 4b [2] 0f 50 [2] 00 4a [2] 1e 57 [2] 1c 56 [2] 07 50 [2] 1b 57 [2] 07 78 }

  condition:
    any of them
}