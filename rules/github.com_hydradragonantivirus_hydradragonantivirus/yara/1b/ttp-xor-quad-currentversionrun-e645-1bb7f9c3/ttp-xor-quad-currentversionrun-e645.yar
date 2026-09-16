rule TTP_XOR_QUAD_CurrentVersionRun_e645 {
  strings:
    $key_e645 = { b5 2a [2] 91 24 [2] ba 08 [2] 94 2a [2] 80 31 [2] 8f 2b [2] 91 36 [2] 93 37 [2] 88 31 [2] 94 36 [2] 88 19 }

  condition:
    any of them
}