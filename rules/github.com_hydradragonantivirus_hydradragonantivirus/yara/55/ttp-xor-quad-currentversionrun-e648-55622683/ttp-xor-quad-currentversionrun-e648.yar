rule TTP_XOR_QUAD_CurrentVersionRun_e648 {
  strings:
    $key_e648 = { b5 27 [2] 91 29 [2] ba 05 [2] 94 27 [2] 80 3c [2] 8f 26 [2] 91 3b [2] 93 3a [2] 88 3c [2] 94 3b [2] 88 14 }

  condition:
    any of them
}