rule TTP_XOR_MULT_DOSStub_b265 {
  strings:
    $key_b265 = { e6 0d [2] 92 15 [2] d5 17 [2] 92 06 [2] dc 0a [2] d0 00 [2] c7 0b [2] dc 45 [2] e1 }

  condition:
    any of them
}