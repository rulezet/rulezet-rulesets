rule TTP_XOR_QUAD_CurrentVersionRun_3045 {
  strings:
    $key_3045 = { 63 2a [2] 47 24 [2] 6c 08 [2] 42 2a [2] 56 31 [2] 59 2b [2] 47 36 [2] 45 37 [2] 5e 31 [2] 42 36 [2] 5e 19 }

  condition:
    any of them
}