rule TTP_XOR_MULT_DOSStub_c507 {
  strings:
    $key_c507 = { 91 6f [2] e5 77 [2] a2 75 [2] e5 64 [2] ab 68 [2] a7 62 [2] b0 69 [2] ab 27 [2] 96 }

  condition:
    any of them
}