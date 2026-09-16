rule TTP_XOR_QUAD_CurrentVersionRun_fa35 {
  strings:
    $key_fa35 = { a9 5a [2] 8d 54 [2] a6 78 [2] 88 5a [2] 9c 41 [2] 93 5b [2] 8d 46 [2] 8f 47 [2] 94 41 [2] 88 46 [2] 94 69 }

  condition:
    any of them
}