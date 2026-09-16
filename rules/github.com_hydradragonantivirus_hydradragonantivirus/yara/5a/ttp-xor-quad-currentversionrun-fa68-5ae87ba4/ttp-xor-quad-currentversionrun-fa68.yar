rule TTP_XOR_QUAD_CurrentVersionRun_fa68 {
  strings:
    $key_fa68 = { a9 07 [2] 8d 09 [2] a6 25 [2] 88 07 [2] 9c 1c [2] 93 06 [2] 8d 1b [2] 8f 1a [2] 94 1c [2] 88 1b [2] 94 34 }

  condition:
    any of them
}