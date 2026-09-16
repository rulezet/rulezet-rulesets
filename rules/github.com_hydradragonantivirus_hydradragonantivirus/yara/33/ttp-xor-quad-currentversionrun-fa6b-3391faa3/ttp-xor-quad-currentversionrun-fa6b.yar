rule TTP_XOR_QUAD_CurrentVersionRun_fa6b {
  strings:
    $key_fa6b = { a9 04 [2] 8d 0a [2] a6 26 [2] 88 04 [2] 9c 1f [2] 93 05 [2] 8d 18 [2] 8f 19 [2] 94 1f [2] 88 18 [2] 94 37 }

  condition:
    any of them
}