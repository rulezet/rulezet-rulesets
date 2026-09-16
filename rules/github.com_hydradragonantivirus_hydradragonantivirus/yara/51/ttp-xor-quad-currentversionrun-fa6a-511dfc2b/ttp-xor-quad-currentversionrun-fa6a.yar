rule TTP_XOR_QUAD_CurrentVersionRun_fa6a {
  strings:
    $key_fa6a = { a9 05 [2] 8d 0b [2] a6 27 [2] 88 05 [2] 9c 1e [2] 93 04 [2] 8d 19 [2] 8f 18 [2] 94 1e [2] 88 19 [2] 94 36 }

  condition:
    any of them
}