rule TTP_XOR_MULT_DOSStub_c520 {
  strings:
    $key_c520 = { 91 48 [2] e5 50 [2] a2 52 [2] e5 43 [2] ab 4f [2] a7 45 [2] b0 4e [2] ab 00 [2] 96 }

  condition:
    any of them
}