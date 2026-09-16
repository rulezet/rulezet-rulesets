rule TTP_XOR_QUAD_CurrentVersionRun_fa28 {
  strings:
    $key_fa28 = { a9 47 [2] 8d 49 [2] a6 65 [2] 88 47 [2] 9c 5c [2] 93 46 [2] 8d 5b [2] 8f 5a [2] 94 5c [2] 88 5b [2] 94 74 }

  condition:
    any of them
}