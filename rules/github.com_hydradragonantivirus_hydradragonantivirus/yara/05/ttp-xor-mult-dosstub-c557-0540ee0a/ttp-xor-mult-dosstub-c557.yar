rule TTP_XOR_MULT_DOSStub_c557 {
  strings:
    $key_c557 = { 91 3f [2] e5 27 [2] a2 25 [2] e5 34 [2] ab 38 [2] a7 32 [2] b0 39 [2] ab 77 [2] 96 }

  condition:
    any of them
}