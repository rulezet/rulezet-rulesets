rule TTP_XOR_MULT_DOSStub_c639 {
  strings:
    $key_c639 = { 92 51 [2] e6 49 [2] a1 4b [2] e6 5a [2] a8 56 [2] a4 5c [2] b3 57 [2] a8 19 [2] 95 }

  condition:
    any of them
}