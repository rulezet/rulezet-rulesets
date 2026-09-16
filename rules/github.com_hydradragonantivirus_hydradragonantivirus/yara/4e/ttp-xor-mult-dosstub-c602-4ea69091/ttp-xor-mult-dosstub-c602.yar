rule TTP_XOR_MULT_DOSStub_c602 {
  strings:
    $key_c602 = { 92 6a [2] e6 72 [2] a1 70 [2] e6 61 [2] a8 6d [2] a4 67 [2] b3 6c [2] a8 22 [2] 95 }

  condition:
    any of them
}