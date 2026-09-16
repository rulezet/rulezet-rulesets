rule TTP_XOR_QUAD_CurrentVersionRun_fa24 {
  strings:
    $key_fa24 = { a9 4b [2] 8d 45 [2] a6 69 [2] 88 4b [2] 9c 50 [2] 93 4a [2] 8d 57 [2] 8f 56 [2] 94 50 [2] 88 57 [2] 94 78 }

  condition:
    any of them
}