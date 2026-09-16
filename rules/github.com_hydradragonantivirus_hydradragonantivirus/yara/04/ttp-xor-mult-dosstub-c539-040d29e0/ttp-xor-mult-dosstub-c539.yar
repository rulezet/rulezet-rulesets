rule TTP_XOR_MULT_DOSStub_c539 {
  strings:
    $key_c539 = { 91 51 [2] e5 49 [2] a2 4b [2] e5 5a [2] ab 56 [2] a7 5c [2] b0 57 [2] ab 19 [2] 96 }

  condition:
    any of them
}