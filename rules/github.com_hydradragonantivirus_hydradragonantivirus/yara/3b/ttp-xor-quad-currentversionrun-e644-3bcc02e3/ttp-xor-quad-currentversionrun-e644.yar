rule TTP_XOR_QUAD_CurrentVersionRun_e644 {
  strings:
    $key_e644 = { b5 2b [2] 91 25 [2] ba 09 [2] 94 2b [2] 80 30 [2] 8f 2a [2] 91 37 [2] 93 36 [2] 88 30 [2] 94 37 [2] 88 18 }

  condition:
    any of them
}