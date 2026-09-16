rule TTP_XOR_MULT_DOSStub_c536 {
  strings:
    $key_c536 = { 91 5e [2] e5 46 [2] a2 44 [2] e5 55 [2] ab 59 [2] a7 53 [2] b0 58 [2] ab 16 [2] 96 }

  condition:
    any of them
}