rule TTP_XOR_QUAD_CurrentVersionRun_fa3f {
  strings:
    $key_fa3f = { a9 50 [2] 8d 5e [2] a6 72 [2] 88 50 [2] 9c 4b [2] 93 51 [2] 8d 4c [2] 8f 4d [2] 94 4b [2] 88 4c [2] 94 63 }

  condition:
    any of them
}