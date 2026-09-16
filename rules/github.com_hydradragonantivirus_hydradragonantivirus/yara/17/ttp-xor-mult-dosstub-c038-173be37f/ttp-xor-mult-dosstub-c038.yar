rule TTP_XOR_MULT_DOSStub_c038 {
  strings:
    $key_c038 = { 94 50 [2] e0 48 [2] a7 4a [2] e0 5b [2] ae 57 [2] a2 5d [2] b5 56 [2] ae 18 [2] 93 }

  condition:
    any of them
}