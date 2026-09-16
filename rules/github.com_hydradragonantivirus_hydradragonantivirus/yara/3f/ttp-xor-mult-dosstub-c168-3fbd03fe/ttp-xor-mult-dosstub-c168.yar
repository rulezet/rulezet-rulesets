rule TTP_XOR_MULT_DOSStub_c168 {
  strings:
    $key_c168 = { 95 00 [2] e1 18 [2] a6 1a [2] e1 0b [2] af 07 [2] a3 0d [2] b4 06 [2] af 48 [2] 92 }

  condition:
    any of them
}