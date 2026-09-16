rule TTP_XOR_QUAD_CurrentVersionRun_6b45 {
  strings:
    $key_6b45 = { 38 2a [2] 1c 24 [2] 37 08 [2] 19 2a [2] 0d 31 [2] 02 2b [2] 1c 36 [2] 1e 37 [2] 05 31 [2] 19 36 [2] 05 19 }

  condition:
    any of them
}