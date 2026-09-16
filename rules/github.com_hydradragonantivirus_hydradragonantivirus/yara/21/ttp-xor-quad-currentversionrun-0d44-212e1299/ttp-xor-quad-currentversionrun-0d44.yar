rule TTP_XOR_QUAD_CurrentVersionRun_0d44 {
  strings:
    $key_0d44 = { 5e 2b [2] 7a 25 [2] 51 09 [2] 7f 2b [2] 6b 30 [2] 64 2a [2] 7a 37 [2] 78 36 [2] 63 30 [2] 7f 37 [2] 63 18 }

  condition:
    any of them
}