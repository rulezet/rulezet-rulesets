rule TTP_XOR_QUAD_CurrentVersionRun_0374 {
  strings:
    $key_0374 = { 50 1b [2] 74 15 [2] 5f 39 [2] 71 1b [2] 65 00 [2] 6a 1a [2] 74 07 [2] 76 06 [2] 6d 00 [2] 71 07 [2] 6d 28 }

  condition:
    any of them
}