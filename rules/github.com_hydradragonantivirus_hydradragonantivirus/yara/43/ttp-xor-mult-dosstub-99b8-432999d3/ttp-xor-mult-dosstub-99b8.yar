rule TTP_XOR_MULT_DOSStub_99b8 {
  strings:
    $key_99b8 = { cd d0 [2] b9 c8 [2] fe ca [2] b9 db [2] f7 d7 [2] fb dd [2] ec d6 [2] f7 98 [2] ca }

  condition:
    any of them
}