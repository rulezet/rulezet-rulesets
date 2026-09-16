rule TTP_XOR_QUAD_CurrentVersionRun_f825 {
  strings:
    $key_f825 = { ab 4a [2] 8f 44 [2] a4 68 [2] 8a 4a [2] 9e 51 [2] 91 4b [2] 8f 56 [2] 8d 57 [2] 96 51 [2] 8a 56 [2] 96 79 }

  condition:
    any of them
}