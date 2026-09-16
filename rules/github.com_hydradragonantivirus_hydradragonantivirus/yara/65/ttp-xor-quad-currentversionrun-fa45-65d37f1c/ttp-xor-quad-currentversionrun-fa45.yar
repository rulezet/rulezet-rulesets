rule TTP_XOR_QUAD_CurrentVersionRun_fa45 {
  strings:
    $key_fa45 = { a9 2a [2] 8d 24 [2] a6 08 [2] 88 2a [2] 9c 31 [2] 93 2b [2] 8d 36 [2] 8f 37 [2] 94 31 [2] 88 36 [2] 94 19 }

  condition:
    any of them
}