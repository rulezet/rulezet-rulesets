rule TTP_XOR_MULT_DOSStub_91ab {
  strings:
    $key_91ab = { c5 c3 [2] b1 db [2] f6 d9 [2] b1 c8 [2] ff c4 [2] f3 ce [2] e4 c5 [2] ff 8b [2] c2 }

  condition:
    any of them
}