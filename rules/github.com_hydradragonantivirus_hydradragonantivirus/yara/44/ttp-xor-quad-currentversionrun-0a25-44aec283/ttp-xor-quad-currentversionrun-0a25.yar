rule TTP_XOR_QUAD_CurrentVersionRun_0a25 {
  strings:
    $key_0a25 = { 59 4a [2] 7d 44 [2] 56 68 [2] 78 4a [2] 6c 51 [2] 63 4b [2] 7d 56 [2] 7f 57 [2] 64 51 [2] 78 56 [2] 64 79 }

  condition:
    any of them
}