rule TTP_XOR_QUAD_CurrentVersionRun_fa4a {
  strings:
    $key_fa4a = { a9 25 [2] 8d 2b [2] a6 07 [2] 88 25 [2] 9c 3e [2] 93 24 [2] 8d 39 [2] 8f 38 [2] 94 3e [2] 88 39 [2] 94 16 }

  condition:
    any of them
}