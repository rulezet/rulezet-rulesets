rule TTP_XOR_QUAD_CurrentVersionRun_0f05 {
  strings:
    $key_0f05 = { 5c 6a [2] 78 64 [2] 53 48 [2] 7d 6a [2] 69 71 [2] 66 6b [2] 78 76 [2] 7a 77 [2] 61 71 [2] 7d 76 [2] 61 59 }

  condition:
    any of them
}