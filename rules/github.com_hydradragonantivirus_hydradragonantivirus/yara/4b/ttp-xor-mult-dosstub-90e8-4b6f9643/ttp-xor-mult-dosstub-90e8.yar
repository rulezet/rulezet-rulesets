rule TTP_XOR_MULT_DOSStub_90e8 {
  strings:
    $key_90e8 = { c4 80 [2] b0 98 [2] f7 9a [2] b0 8b [2] fe 87 [2] f2 8d [2] e5 86 [2] fe c8 [2] c3 }

  condition:
    any of them
}