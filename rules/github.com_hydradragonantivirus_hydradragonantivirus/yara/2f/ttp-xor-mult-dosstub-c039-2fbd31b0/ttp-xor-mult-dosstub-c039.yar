rule TTP_XOR_MULT_DOSStub_c039 {
  strings:
    $key_c039 = { 94 51 [2] e0 49 [2] a7 4b [2] e0 5a [2] ae 56 [2] a2 5c [2] b5 57 [2] ae 19 [2] 93 }

  condition:
    any of them
}