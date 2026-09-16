rule TTP_XOR_MULT_DOSStub_c5e7 {
  strings:
    $key_c5e7 = { 91 8f [2] e5 97 [2] a2 95 [2] e5 84 [2] ab 88 [2] a7 82 [2] b0 89 [2] ab c7 [2] 96 }

  condition:
    any of them
}