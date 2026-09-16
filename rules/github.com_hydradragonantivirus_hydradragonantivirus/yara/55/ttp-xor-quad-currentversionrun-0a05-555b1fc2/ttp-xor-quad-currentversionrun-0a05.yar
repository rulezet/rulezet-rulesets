rule TTP_XOR_QUAD_CurrentVersionRun_0a05 {
  strings:
    $key_0a05 = { 59 6a [2] 7d 64 [2] 56 48 [2] 78 6a [2] 6c 71 [2] 63 6b [2] 7d 76 [2] 7f 77 [2] 64 71 [2] 78 76 [2] 64 59 }

  condition:
    any of them
}