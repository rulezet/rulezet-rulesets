rule TTP_XOR_QUAD_CurrentVersionRun_0514 {
  strings:
    $key_0514 = { 56 7b [2] 72 75 [2] 59 59 [2] 77 7b [2] 63 60 [2] 6c 7a [2] 72 67 [2] 70 66 [2] 6b 60 [2] 77 67 [2] 6b 48 }

  condition:
    any of them
}