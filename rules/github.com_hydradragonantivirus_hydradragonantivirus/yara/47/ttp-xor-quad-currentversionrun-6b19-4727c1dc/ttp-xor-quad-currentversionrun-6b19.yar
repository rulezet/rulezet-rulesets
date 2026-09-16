rule TTP_XOR_QUAD_CurrentVersionRun_6b19 {
  strings:
    $key_6b19 = { 38 76 [2] 1c 78 [2] 37 54 [2] 19 76 [2] 0d 6d [2] 02 77 [2] 1c 6a [2] 1e 6b [2] 05 6d [2] 19 6a [2] 05 45 }

  condition:
    any of them
}