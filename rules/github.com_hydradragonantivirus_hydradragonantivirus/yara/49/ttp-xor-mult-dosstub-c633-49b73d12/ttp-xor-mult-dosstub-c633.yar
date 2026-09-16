rule TTP_XOR_MULT_DOSStub_c633 {
  strings:
    $key_c633 = { 92 5b [2] e6 43 [2] a1 41 [2] e6 50 [2] a8 5c [2] a4 56 [2] b3 5d [2] a8 13 [2] 95 }

  condition:
    any of them
}