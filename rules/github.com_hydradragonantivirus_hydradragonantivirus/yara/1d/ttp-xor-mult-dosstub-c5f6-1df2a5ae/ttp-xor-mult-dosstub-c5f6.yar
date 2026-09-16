rule TTP_XOR_MULT_DOSStub_c5f6 {
  strings:
    $key_c5f6 = { 91 9e [2] e5 86 [2] a2 84 [2] e5 95 [2] ab 99 [2] a7 93 [2] b0 98 [2] ab d6 [2] 96 }

  condition:
    any of them
}