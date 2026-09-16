rule TTP_XOR_QUAD_CurrentVersionRun_fa0e {
  strings:
    $key_fa0e = { a9 61 [2] 8d 6f [2] a6 43 [2] 88 61 [2] 9c 7a [2] 93 60 [2] 8d 7d [2] 8f 7c [2] 94 7a [2] 88 7d [2] 94 52 }

  condition:
    any of them
}