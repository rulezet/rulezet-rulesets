rule TTP_XOR_QUAD_CurrentVersionRun_6b48 {
  strings:
    $key_6b48 = { 38 27 [2] 1c 29 [2] 37 05 [2] 19 27 [2] 0d 3c [2] 02 26 [2] 1c 3b [2] 1e 3a [2] 05 3c [2] 19 3b [2] 05 14 }

  condition:
    any of them
}