rule TTP_XOR_QUAD_CurrentVersionRun_5aff {
  strings:
    $key_5aff = { 09 90 [2] 2d 9e [2] 06 b2 [2] 28 90 [2] 3c 8b [2] 33 91 [2] 2d 8c [2] 2f 8d [2] 34 8b [2] 28 8c [2] 34 a3 }

  condition:
    any of them
}