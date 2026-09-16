rule TTP_XOR_QUAD_CurrentVersionRun_1cff {
  strings:
    $key_1cff = { 4f 90 [2] 6b 9e [2] 40 b2 [2] 6e 90 [2] 7a 8b [2] 75 91 [2] 6b 8c [2] 69 8d [2] 72 8b [2] 6e 8c [2] 72 a3 }

  condition:
    any of them
}