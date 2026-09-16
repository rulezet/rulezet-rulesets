rule TTP_XOR_QUAD_CurrentVersionRun_f5fe {
  strings:
    $key_f5fe = { a6 91 [2] 82 9f [2] a9 b3 [2] 87 91 [2] 93 8a [2] 9c 90 [2] 82 8d [2] 80 8c [2] 9b 8a [2] 87 8d [2] 9b a2 }

  condition:
    any of them
}