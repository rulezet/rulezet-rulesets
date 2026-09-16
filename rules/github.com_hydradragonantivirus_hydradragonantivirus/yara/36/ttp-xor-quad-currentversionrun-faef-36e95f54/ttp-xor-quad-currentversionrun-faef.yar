rule TTP_XOR_QUAD_CurrentVersionRun_faef {
  strings:
    $key_faef = { a9 80 [2] 8d 8e [2] a6 a2 [2] 88 80 [2] 9c 9b [2] 93 81 [2] 8d 9c [2] 8f 9d [2] 94 9b [2] 88 9c [2] 94 b3 }

  condition:
    any of them
}