rule TTP_XOR_QUAD_CurrentVersionRun_6c68 {
  strings:
    $key_6c68 = { 3f 07 [2] 1b 09 [2] 30 25 [2] 1e 07 [2] 0a 1c [2] 05 06 [2] 1b 1b [2] 19 1a [2] 02 1c [2] 1e 1b [2] 02 34 }

  condition:
    any of them
}