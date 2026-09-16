rule TTP_XOR_QUAD_CurrentVersionRun_0a79 {
  strings:
    $key_0a79 = { 59 16 [2] 7d 18 [2] 56 34 [2] 78 16 [2] 6c 0d [2] 63 17 [2] 7d 0a [2] 7f 0b [2] 64 0d [2] 78 0a [2] 64 25 }

  condition:
    any of them
}