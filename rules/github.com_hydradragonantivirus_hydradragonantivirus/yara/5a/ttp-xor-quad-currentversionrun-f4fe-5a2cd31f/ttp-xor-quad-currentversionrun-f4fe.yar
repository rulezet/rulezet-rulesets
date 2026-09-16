rule TTP_XOR_QUAD_CurrentVersionRun_f4fe {
  strings:
    $key_f4fe = { a7 91 [2] 83 9f [2] a8 b3 [2] 86 91 [2] 92 8a [2] 9d 90 [2] 83 8d [2] 81 8c [2] 9a 8a [2] 86 8d [2] 9a a2 }

  condition:
    any of them
}