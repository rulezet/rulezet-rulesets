rule TTP_XOR_QUAD_CurrentVersionRun_f4fc {
  strings:
    $key_f4fc = { a7 93 [2] 83 9d [2] a8 b1 [2] 86 93 [2] 92 88 [2] 9d 92 [2] 83 8f [2] 81 8e [2] 9a 88 [2] 86 8f [2] 9a a0 }

  condition:
    any of them
}