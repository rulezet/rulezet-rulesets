rule TTP_XOR_QUAD_CurrentVersionRun_faee {
  strings:
    $key_faee = { a9 81 [2] 8d 8f [2] a6 a3 [2] 88 81 [2] 9c 9a [2] 93 80 [2] 8d 9d [2] 8f 9c [2] 94 9a [2] 88 9d [2] 94 b2 }

  condition:
    any of them
}