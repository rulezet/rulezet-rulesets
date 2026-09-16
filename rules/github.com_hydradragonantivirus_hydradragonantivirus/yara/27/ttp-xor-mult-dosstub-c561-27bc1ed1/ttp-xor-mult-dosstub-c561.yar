rule TTP_XOR_MULT_DOSStub_c561 {
  strings:
    $key_c561 = { 91 09 [2] e5 11 [2] a2 13 [2] e5 02 [2] ab 0e [2] a7 04 [2] b0 0f [2] ab 41 [2] 96 }

  condition:
    any of them
}