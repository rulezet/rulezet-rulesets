rule TTP_XOR_QUAD_CurrentVersionRun_0005 {
  strings:
    $key_0005 = { 53 6a [2] 77 64 [2] 5c 48 [2] 72 6a [2] 66 71 [2] 69 6b [2] 77 76 [2] 75 77 [2] 6e 71 [2] 72 76 [2] 6e 59 }

  condition:
    any of them
}