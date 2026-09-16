rule TTP_XOR_MULT_DOSStub_c510 {
  strings:
    $key_c510 = { 91 78 [2] e5 60 [2] a2 62 [2] e5 73 [2] ab 7f [2] a7 75 [2] b0 7e [2] ab 30 [2] 96 }

  condition:
    any of them
}