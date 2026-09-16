rule TTP_XOR_QUAD_CurrentVersionRun_6a48 {
  strings:
    $key_6a48 = { 39 27 [2] 1d 29 [2] 36 05 [2] 18 27 [2] 0c 3c [2] 03 26 [2] 1d 3b [2] 1f 3a [2] 04 3c [2] 18 3b [2] 04 14 }

  condition:
    any of them
}