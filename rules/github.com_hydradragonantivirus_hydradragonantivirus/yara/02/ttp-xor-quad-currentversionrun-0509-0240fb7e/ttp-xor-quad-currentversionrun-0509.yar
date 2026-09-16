rule TTP_XOR_QUAD_CurrentVersionRun_0509 {
  strings:
    $key_0509 = { 56 66 [2] 72 68 [2] 59 44 [2] 77 66 [2] 63 7d [2] 6c 67 [2] 72 7a [2] 70 7b [2] 6b 7d [2] 77 7a [2] 6b 55 }

  condition:
    any of them
}