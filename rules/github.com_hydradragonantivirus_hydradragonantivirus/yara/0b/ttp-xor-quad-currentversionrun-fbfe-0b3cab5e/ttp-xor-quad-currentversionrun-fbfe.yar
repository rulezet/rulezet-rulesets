rule TTP_XOR_QUAD_CurrentVersionRun_fbfe {
  strings:
    $key_fbfe = { a8 91 [2] 8c 9f [2] a7 b3 [2] 89 91 [2] 9d 8a [2] 92 90 [2] 8c 8d [2] 8e 8c [2] 95 8a [2] 89 8d [2] 95 a2 }

  condition:
    any of them
}