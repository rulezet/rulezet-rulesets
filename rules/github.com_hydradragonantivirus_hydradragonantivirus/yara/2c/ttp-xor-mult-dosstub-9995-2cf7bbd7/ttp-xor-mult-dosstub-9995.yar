rule TTP_XOR_MULT_DOSStub_9995 {
  strings:
    $key_9995 = { cd fd [2] b9 e5 [2] fe e7 [2] b9 f6 [2] f7 fa [2] fb f0 [2] ec fb [2] f7 b5 [2] ca }

  condition:
    any of them
}