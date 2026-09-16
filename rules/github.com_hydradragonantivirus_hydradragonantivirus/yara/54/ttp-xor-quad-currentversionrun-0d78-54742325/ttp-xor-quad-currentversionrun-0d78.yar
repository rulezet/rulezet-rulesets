rule TTP_XOR_QUAD_CurrentVersionRun_0d78 {
  strings:
    $key_0d78 = { 5e 17 [2] 7a 19 [2] 51 35 [2] 7f 17 [2] 6b 0c [2] 64 16 [2] 7a 0b [2] 78 0a [2] 63 0c [2] 7f 0b [2] 63 24 }

  condition:
    any of them
}