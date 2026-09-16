rule TTP_XOR_QUAD_CurrentVersionRun_0519 {
  strings:
    $key_0519 = { 56 76 [2] 72 78 [2] 59 54 [2] 77 76 [2] 63 6d [2] 6c 77 [2] 72 6a [2] 70 6b [2] 6b 6d [2] 77 6a [2] 6b 45 }

  condition:
    any of them
}