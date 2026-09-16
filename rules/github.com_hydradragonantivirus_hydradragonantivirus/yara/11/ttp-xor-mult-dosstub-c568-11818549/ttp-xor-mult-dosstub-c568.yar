rule TTP_XOR_MULT_DOSStub_c568 {
  strings:
    $key_c568 = { 91 00 [2] e5 18 [2] a2 1a [2] e5 0b [2] ab 07 [2] a7 0d [2] b0 06 [2] ab 48 [2] 96 }

  condition:
    any of them
}