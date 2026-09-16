rule TTP_XOR_MULT_DOSStub_c664 {
  strings:
    $key_c664 = { 92 0c [2] e6 14 [2] a1 16 [2] e6 07 [2] a8 0b [2] a4 01 [2] b3 0a [2] a8 44 [2] 95 }

  condition:
    any of them
}