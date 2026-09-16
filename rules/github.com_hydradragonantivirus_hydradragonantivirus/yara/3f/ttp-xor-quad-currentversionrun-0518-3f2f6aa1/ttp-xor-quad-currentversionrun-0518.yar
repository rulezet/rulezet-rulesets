rule TTP_XOR_QUAD_CurrentVersionRun_0518 {
  strings:
    $key_0518 = { 56 77 [2] 72 79 [2] 59 55 [2] 77 77 [2] 63 6c [2] 6c 76 [2] 72 6b [2] 70 6a [2] 6b 6c [2] 77 6b [2] 6b 44 }

  condition:
    any of them
}