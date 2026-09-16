rule TTP_XOR_QUAD_CurrentVersionRun_fa4d {
  strings:
    $key_fa4d = { a9 22 [2] 8d 2c [2] a6 00 [2] 88 22 [2] 9c 39 [2] 93 23 [2] 8d 3e [2] 8f 3f [2] 94 39 [2] 88 3e [2] 94 11 }

  condition:
    any of them
}