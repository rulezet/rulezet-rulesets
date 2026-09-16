rule TTP_XOR_QUAD_CurrentVersionRun_f848 {
  strings:
    $key_f848 = { ab 27 [2] 8f 29 [2] a4 05 [2] 8a 27 [2] 9e 3c [2] 91 26 [2] 8f 3b [2] 8d 3a [2] 96 3c [2] 8a 3b [2] 96 14 }

  condition:
    any of them
}