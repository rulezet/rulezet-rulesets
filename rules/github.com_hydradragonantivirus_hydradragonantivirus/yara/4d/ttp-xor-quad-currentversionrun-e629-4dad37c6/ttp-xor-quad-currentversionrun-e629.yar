rule TTP_XOR_QUAD_CurrentVersionRun_e629 {
  strings:
    $key_e629 = { b5 46 [2] 91 48 [2] ba 64 [2] 94 46 [2] 80 5d [2] 8f 47 [2] 91 5a [2] 93 5b [2] 88 5d [2] 94 5a [2] 88 75 }

  condition:
    any of them
}