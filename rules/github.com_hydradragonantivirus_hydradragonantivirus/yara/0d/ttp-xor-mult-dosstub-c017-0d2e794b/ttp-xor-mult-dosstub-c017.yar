rule TTP_XOR_MULT_DOSStub_c017 {
  strings:
    $key_c017 = { 94 7f [2] e0 67 [2] a7 65 [2] e0 74 [2] ae 78 [2] a2 72 [2] b5 79 [2] ae 37 [2] 93 }

  condition:
    any of them
}