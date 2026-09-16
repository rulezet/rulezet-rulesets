rule TTP_XOR_QUAD_CurrentVersionRun_3705 {
  strings:
    $key_3705 = { 64 6a [2] 40 64 [2] 6b 48 [2] 45 6a [2] 51 71 [2] 5e 6b [2] 40 76 [2] 42 77 [2] 59 71 [2] 45 76 [2] 59 59 }

  condition:
    any of them
}