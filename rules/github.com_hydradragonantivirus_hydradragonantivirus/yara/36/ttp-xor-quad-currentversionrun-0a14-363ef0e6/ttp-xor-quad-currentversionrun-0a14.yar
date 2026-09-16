rule TTP_XOR_QUAD_CurrentVersionRun_0a14 {
  strings:
    $key_0a14 = { 59 7b [2] 7d 75 [2] 56 59 [2] 78 7b [2] 6c 60 [2] 63 7a [2] 7d 67 [2] 7f 66 [2] 64 60 [2] 78 67 [2] 64 48 }

  condition:
    any of them
}