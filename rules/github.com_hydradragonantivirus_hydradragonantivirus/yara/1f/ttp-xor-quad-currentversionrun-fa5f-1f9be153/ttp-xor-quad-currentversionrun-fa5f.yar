rule TTP_XOR_QUAD_CurrentVersionRun_fa5f {
  strings:
    $key_fa5f = { a9 30 [2] 8d 3e [2] a6 12 [2] 88 30 [2] 9c 2b [2] 93 31 [2] 8d 2c [2] 8f 2d [2] 94 2b [2] 88 2c [2] 94 03 }

  condition:
    any of them
}