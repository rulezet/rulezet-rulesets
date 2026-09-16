rule TTP_XOR_QUAD_CurrentVersionRun_0a24 {
  strings:
    $key_0a24 = { 59 4b [2] 7d 45 [2] 56 69 [2] 78 4b [2] 6c 50 [2] 63 4a [2] 7d 57 [2] 7f 56 [2] 64 50 [2] 78 57 [2] 64 78 }

  condition:
    any of them
}