rule TTP_XOR_MULT_DOSStub_90fd {
  strings:
    $key_90fd = { c4 95 [2] b0 8d [2] f7 8f [2] b0 9e [2] fe 92 [2] f2 98 [2] e5 93 [2] fe dd [2] c3 }

  condition:
    any of them
}