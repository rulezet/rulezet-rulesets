rule TTP_XOR_QUAD_CurrentVersionRun_f4ff {
  strings:
    $key_f4ff = { a7 90 [2] 83 9e [2] a8 b2 [2] 86 90 [2] 92 8b [2] 9d 91 [2] 83 8c [2] 81 8d [2] 9a 8b [2] 86 8c [2] 9a a3 }

  condition:
    any of them
}