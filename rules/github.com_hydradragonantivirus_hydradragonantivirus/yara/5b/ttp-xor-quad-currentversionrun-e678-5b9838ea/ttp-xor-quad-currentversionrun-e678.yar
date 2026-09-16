rule TTP_XOR_QUAD_CurrentVersionRun_e678 {
  strings:
    $key_e678 = { b5 17 [2] 91 19 [2] ba 35 [2] 94 17 [2] 80 0c [2] 8f 16 [2] 91 0b [2] 93 0a [2] 88 0c [2] 94 0b [2] 88 24 }

  condition:
    any of them
}