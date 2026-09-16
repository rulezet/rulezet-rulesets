rule TTP_XOR_MULT_DOSStub_c439 {
  strings:
    $key_c439 = { 90 51 [2] e4 49 [2] a3 4b [2] e4 5a [2] aa 56 [2] a6 5c [2] b1 57 [2] aa 19 [2] 97 }

  condition:
    any of them
}