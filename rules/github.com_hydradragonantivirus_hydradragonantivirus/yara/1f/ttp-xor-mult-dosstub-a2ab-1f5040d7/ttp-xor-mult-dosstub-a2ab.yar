rule TTP_XOR_MULT_DOSStub_a2ab {
  strings:
    $key_a2ab = { f6 c3 [2] 82 db [2] c5 d9 [2] 82 c8 [2] cc c4 [2] c0 ce [2] d7 c5 [2] cc 8b [2] f1 }

  condition:
    any of them
}