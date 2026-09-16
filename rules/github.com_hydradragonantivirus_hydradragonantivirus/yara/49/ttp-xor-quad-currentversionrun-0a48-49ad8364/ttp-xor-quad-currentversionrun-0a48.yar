rule TTP_XOR_QUAD_CurrentVersionRun_0a48 {
  strings:
    $key_0a48 = { 59 27 [2] 7d 29 [2] 56 05 [2] 78 27 [2] 6c 3c [2] 63 26 [2] 7d 3b [2] 7f 3a [2] 64 3c [2] 78 3b [2] 64 14 }

  condition:
    any of them
}