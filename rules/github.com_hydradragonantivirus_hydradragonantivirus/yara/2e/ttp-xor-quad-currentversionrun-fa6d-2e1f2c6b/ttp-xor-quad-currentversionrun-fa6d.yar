rule TTP_XOR_QUAD_CurrentVersionRun_fa6d {
  strings:
    $key_fa6d = { a9 02 [2] 8d 0c [2] a6 20 [2] 88 02 [2] 9c 19 [2] 93 03 [2] 8d 1e [2] 8f 1f [2] 94 19 [2] 88 1e [2] 94 31 }

  condition:
    any of them
}