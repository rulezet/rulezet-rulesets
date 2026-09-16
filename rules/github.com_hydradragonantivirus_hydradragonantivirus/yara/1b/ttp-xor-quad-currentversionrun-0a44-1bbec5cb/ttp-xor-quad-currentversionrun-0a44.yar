rule TTP_XOR_QUAD_CurrentVersionRun_0a44 {
  strings:
    $key_0a44 = { 59 2b [2] 7d 25 [2] 56 09 [2] 78 2b [2] 6c 30 [2] 63 2a [2] 7d 37 [2] 7f 36 [2] 64 30 [2] 78 37 [2] 64 18 }

  condition:
    any of them
}