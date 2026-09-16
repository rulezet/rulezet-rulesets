rule TTP_XOR_QUAD_CurrentVersionRun_0a04 {
  strings:
    $key_0a04 = { 59 6b [2] 7d 65 [2] 56 49 [2] 78 6b [2] 6c 70 [2] 63 6a [2] 7d 77 [2] 7f 76 [2] 64 70 [2] 78 77 [2] 64 58 }

  condition:
    any of them
}