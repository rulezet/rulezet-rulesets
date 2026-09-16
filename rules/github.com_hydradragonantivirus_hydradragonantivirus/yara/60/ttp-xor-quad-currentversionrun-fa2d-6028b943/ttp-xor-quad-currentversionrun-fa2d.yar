rule TTP_XOR_QUAD_CurrentVersionRun_fa2d {
  strings:
    $key_fa2d = { a9 42 [2] 8d 4c [2] a6 60 [2] 88 42 [2] 9c 59 [2] 93 43 [2] 8d 5e [2] 8f 5f [2] 94 59 [2] 88 5e [2] 94 71 }

  condition:
    any of them
}