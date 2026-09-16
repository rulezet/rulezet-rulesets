rule TTP_XOR_MULT_DOSStub_c409 {
  strings:
    $key_c409 = { 90 61 [2] e4 79 [2] a3 7b [2] e4 6a [2] aa 66 [2] a6 6c [2] b1 67 [2] aa 29 [2] 97 }

  condition:
    any of them
}