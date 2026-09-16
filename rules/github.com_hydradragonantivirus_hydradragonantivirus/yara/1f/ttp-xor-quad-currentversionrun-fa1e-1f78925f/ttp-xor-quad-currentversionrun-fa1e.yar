rule TTP_XOR_QUAD_CurrentVersionRun_fa1e {
  strings:
    $key_fa1e = { a9 71 [2] 8d 7f [2] a6 53 [2] 88 71 [2] 9c 6a [2] 93 70 [2] 8d 6d [2] 8f 6c [2] 94 6a [2] 88 6d [2] 94 42 }

  condition:
    any of them
}