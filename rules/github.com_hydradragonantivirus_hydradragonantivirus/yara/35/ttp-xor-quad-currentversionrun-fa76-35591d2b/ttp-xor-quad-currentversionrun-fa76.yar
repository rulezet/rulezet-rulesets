rule TTP_XOR_QUAD_CurrentVersionRun_fa76 {
  strings:
    $key_fa76 = { a9 19 [2] 8d 17 [2] a6 3b [2] 88 19 [2] 9c 02 [2] 93 18 [2] 8d 05 [2] 8f 04 [2] 94 02 [2] 88 05 [2] 94 2a }

  condition:
    any of them
}