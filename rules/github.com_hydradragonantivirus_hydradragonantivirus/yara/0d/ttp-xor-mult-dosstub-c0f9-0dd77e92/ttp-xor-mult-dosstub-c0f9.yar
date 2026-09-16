rule TTP_XOR_MULT_DOSStub_c0f9 {
  strings:
    $key_c0f9 = { 94 91 [2] e0 89 [2] a7 8b [2] e0 9a [2] ae 96 [2] a2 9c [2] b5 97 [2] ae d9 [2] 93 }

  condition:
    any of them
}