rule TTP_XOR_MULT_DOSStub_eaab {
  strings:
    $key_eaab = { be c3 [2] ca db [2] 8d d9 [2] ca c8 [2] 84 c4 [2] 88 ce [2] 9f c5 [2] 84 8b [2] b9 }

  condition:
    any of them
}