rule TTP_XOR_MULT_DOSStub_c105 {
  strings:
    $key_c105 = { 95 6d [2] e1 75 [2] a6 77 [2] e1 66 [2] af 6a [2] a3 60 [2] b4 6b [2] af 25 [2] 92 }

  condition:
    any of them
}