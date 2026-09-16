rule TTP_XOR_MULT_DOSStub_c018 {
  strings:
    $key_c018 = { 94 70 [2] e0 68 [2] a7 6a [2] e0 7b [2] ae 77 [2] a2 7d [2] b5 76 [2] ae 38 [2] 93 }

  condition:
    any of them
}