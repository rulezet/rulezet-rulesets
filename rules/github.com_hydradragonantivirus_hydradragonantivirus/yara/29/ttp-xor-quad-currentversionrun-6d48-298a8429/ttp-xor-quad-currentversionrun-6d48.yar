rule TTP_XOR_QUAD_CurrentVersionRun_6d48 {
  strings:
    $key_6d48 = { 3e 27 [2] 1a 29 [2] 31 05 [2] 1f 27 [2] 0b 3c [2] 04 26 [2] 1a 3b [2] 18 3a [2] 03 3c [2] 1f 3b [2] 03 14 }

  condition:
    any of them
}