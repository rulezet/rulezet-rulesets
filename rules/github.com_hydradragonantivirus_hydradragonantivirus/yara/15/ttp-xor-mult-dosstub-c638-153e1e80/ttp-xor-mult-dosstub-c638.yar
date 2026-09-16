rule TTP_XOR_MULT_DOSStub_c638 {
  strings:
    $key_c638 = { 92 50 [2] e6 48 [2] a1 4a [2] e6 5b [2] a8 57 [2] a4 5d [2] b3 56 [2] a8 18 [2] 95 }

  condition:
    any of them
}