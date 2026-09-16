rule TTP_XOR_MULT_DOSStub_9994 {
  strings:
    $key_9994 = { cd fc [2] b9 e4 [2] fe e6 [2] b9 f7 [2] f7 fb [2] fb f1 [2] ec fa [2] f7 b4 [2] ca }

  condition:
    any of them
}