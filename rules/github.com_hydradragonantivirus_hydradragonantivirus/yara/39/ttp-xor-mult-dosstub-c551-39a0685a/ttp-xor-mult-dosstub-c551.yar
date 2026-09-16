rule TTP_XOR_MULT_DOSStub_c551 {
  strings:
    $key_c551 = { 91 39 [2] e5 21 [2] a2 23 [2] e5 32 [2] ab 3e [2] a7 34 [2] b0 3f [2] ab 71 [2] 96 }

  condition:
    any of them
}