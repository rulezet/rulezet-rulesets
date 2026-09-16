rule TTP_XOR_QUAD_CurrentVersionRun_4428 {
  strings:
    $key_4428 = { 17 47 [2] 33 49 [2] 18 65 [2] 36 47 [2] 22 5c [2] 2d 46 [2] 33 5b [2] 31 5a [2] 2a 5c [2] 36 5b [2] 2a 74 }

  condition:
    any of them
}