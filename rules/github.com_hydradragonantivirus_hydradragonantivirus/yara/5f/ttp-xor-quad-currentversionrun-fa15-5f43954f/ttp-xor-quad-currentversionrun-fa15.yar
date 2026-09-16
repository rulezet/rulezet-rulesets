rule TTP_XOR_QUAD_CurrentVersionRun_fa15 {
  strings:
    $key_fa15 = { a9 7a [2] 8d 74 [2] a6 58 [2] 88 7a [2] 9c 61 [2] 93 7b [2] 8d 66 [2] 8f 67 [2] 94 61 [2] 88 66 [2] 94 49 }

  condition:
    any of them
}