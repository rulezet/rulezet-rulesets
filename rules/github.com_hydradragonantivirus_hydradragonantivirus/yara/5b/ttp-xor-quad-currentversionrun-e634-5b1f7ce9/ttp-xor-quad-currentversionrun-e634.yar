rule TTP_XOR_QUAD_CurrentVersionRun_e634 {
  strings:
    $key_e634 = { b5 5b [2] 91 55 [2] ba 79 [2] 94 5b [2] 80 40 [2] 8f 5a [2] 91 47 [2] 93 46 [2] 88 40 [2] 94 47 [2] 88 68 }

  condition:
    any of them
}