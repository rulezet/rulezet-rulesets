rule TTP_XOR_MULT_DOSStub_9993 {
  strings:
    $key_9993 = { cd fb [2] b9 e3 [2] fe e1 [2] b9 f0 [2] f7 fc [2] fb f6 [2] ec fd [2] f7 b3 [2] ca }

  condition:
    any of them
}