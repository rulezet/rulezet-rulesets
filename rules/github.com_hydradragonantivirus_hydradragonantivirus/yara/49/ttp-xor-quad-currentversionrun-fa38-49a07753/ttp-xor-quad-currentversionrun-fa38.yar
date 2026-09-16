rule TTP_XOR_QUAD_CurrentVersionRun_fa38 {
  strings:
    $key_fa38 = { a9 57 [2] 8d 59 [2] a6 75 [2] 88 57 [2] 9c 4c [2] 93 56 [2] 8d 4b [2] 8f 4a [2] 94 4c [2] 88 4b [2] 94 64 }

  condition:
    any of them
}