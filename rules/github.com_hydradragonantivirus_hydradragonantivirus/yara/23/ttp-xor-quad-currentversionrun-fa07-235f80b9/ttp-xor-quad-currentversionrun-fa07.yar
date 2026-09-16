rule TTP_XOR_QUAD_CurrentVersionRun_fa07 {
  strings:
    $key_fa07 = { a9 68 [2] 8d 66 [2] a6 4a [2] 88 68 [2] 9c 73 [2] 93 69 [2] 8d 74 [2] 8f 75 [2] 94 73 [2] 88 74 [2] 94 5b }

  condition:
    any of them
}