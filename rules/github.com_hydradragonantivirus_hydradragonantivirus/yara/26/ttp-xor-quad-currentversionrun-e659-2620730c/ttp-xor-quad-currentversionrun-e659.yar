rule TTP_XOR_QUAD_CurrentVersionRun_e659 {
  strings:
    $key_e659 = { b5 36 [2] 91 38 [2] ba 14 [2] 94 36 [2] 80 2d [2] 8f 37 [2] 91 2a [2] 93 2b [2] 88 2d [2] 94 2a [2] 88 05 }

  condition:
    any of them
}