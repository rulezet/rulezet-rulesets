rule TTP_XOR_QUAD_CurrentVersionRun_e668 {
  strings:
    $key_e668 = { b5 07 [2] 91 09 [2] ba 25 [2] 94 07 [2] 80 1c [2] 8f 06 [2] 91 1b [2] 93 1a [2] 88 1c [2] 94 1b [2] 88 34 }

  condition:
    any of them
}