rule TTP_XOR_QUAD_CurrentVersionRun_0d55 {
  strings:
    $key_0d55 = { 5e 3a [2] 7a 34 [2] 51 18 [2] 7f 3a [2] 6b 21 [2] 64 3b [2] 7a 26 [2] 78 27 [2] 63 21 [2] 7f 26 [2] 63 09 }

  condition:
    any of them
}