rule TTP_XOR_QUAD_CurrentVersionRun_0af8 {
  strings:
    $key_0af8 = { 59 97 [2] 7d 99 [2] 56 b5 [2] 78 97 [2] 6c 8c [2] 63 96 [2] 7d 8b [2] 7f 8a [2] 64 8c [2] 78 8b [2] 64 a4 }

  condition:
    any of them
}