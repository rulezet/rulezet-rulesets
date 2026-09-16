rule TTP_XOR_QUAD_CurrentVersionRun_fa6c {
  strings:
    $key_fa6c = { a9 03 [2] 8d 0d [2] a6 21 [2] 88 03 [2] 9c 18 [2] 93 02 [2] 8d 1f [2] 8f 1e [2] 94 18 [2] 88 1f [2] 94 30 }

  condition:
    any of them
}