rule TTP_XOR_QUAD_CurrentVersionRun_e614 {
  strings:
    $key_e614 = { b5 7b [2] 91 75 [2] ba 59 [2] 94 7b [2] 80 60 [2] 8f 7a [2] 91 67 [2] 93 66 [2] 88 60 [2] 94 67 [2] 88 48 }

  condition:
    any of them
}