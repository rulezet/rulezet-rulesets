rule TTP_XOR_MULT_DOSStub_c5aa {
  strings:
    $key_c5aa = { 91 c2 [2] e5 da [2] a2 d8 [2] e5 c9 [2] ab c5 [2] a7 cf [2] b0 c4 [2] ab 8a [2] 96 }

  condition:
    any of them
}