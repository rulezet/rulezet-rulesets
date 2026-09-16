rule TTP_XOR_MULT_DOSStub_c0ab {
  strings:
    $key_c0ab = { 94 c3 [2] e0 db [2] a7 d9 [2] e0 c8 [2] ae c4 [2] a2 ce [2] b5 c5 [2] ae 8b [2] 93 }

  condition:
    any of them
}