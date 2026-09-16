rule TTP_XOR_MULT_DOSStub_c5e1 {
  strings:
    $key_c5e1 = { 91 89 [2] e5 91 [2] a2 93 [2] e5 82 [2] ab 8e [2] a7 84 [2] b0 8f [2] ab c1 [2] 96 }

  condition:
    any of them
}