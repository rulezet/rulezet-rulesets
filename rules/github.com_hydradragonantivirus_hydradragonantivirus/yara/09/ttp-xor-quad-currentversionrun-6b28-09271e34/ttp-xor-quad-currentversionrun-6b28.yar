rule TTP_XOR_QUAD_CurrentVersionRun_6b28 {
  strings:
    $key_6b28 = { 38 47 [2] 1c 49 [2] 37 65 [2] 19 47 [2] 0d 5c [2] 02 46 [2] 1c 5b [2] 1e 5a [2] 05 5c [2] 19 5b [2] 05 74 }

  condition:
    any of them
}