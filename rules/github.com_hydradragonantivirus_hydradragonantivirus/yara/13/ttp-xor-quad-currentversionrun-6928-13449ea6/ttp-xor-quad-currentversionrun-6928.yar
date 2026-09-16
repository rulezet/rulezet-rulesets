rule TTP_XOR_QUAD_CurrentVersionRun_6928 {
  strings:
    $key_6928 = { 3a 47 [2] 1e 49 [2] 35 65 [2] 1b 47 [2] 0f 5c [2] 00 46 [2] 1e 5b [2] 1c 5a [2] 07 5c [2] 1b 5b [2] 07 74 }

  condition:
    any of them
}