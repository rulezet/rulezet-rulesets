rule TTP_XOR_QUAD_CurrentVersionRun_e658 {
  strings:
    $key_e658 = { b5 37 [2] 91 39 [2] ba 15 [2] 94 37 [2] 80 2c [2] 8f 36 [2] 91 2b [2] 93 2a [2] 88 2c [2] 94 2b [2] 88 04 }

  condition:
    any of them
}