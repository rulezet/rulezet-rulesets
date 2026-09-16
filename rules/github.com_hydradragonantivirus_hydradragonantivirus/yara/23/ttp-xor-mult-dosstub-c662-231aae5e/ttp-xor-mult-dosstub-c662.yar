rule TTP_XOR_MULT_DOSStub_c662 {
  strings:
    $key_c662 = { 92 0a [2] e6 12 [2] a1 10 [2] e6 01 [2] a8 0d [2] a4 07 [2] b3 0c [2] a8 42 [2] 95 }

  condition:
    any of them
}