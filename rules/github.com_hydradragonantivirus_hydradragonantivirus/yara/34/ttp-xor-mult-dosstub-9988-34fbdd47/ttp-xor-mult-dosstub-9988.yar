rule TTP_XOR_MULT_DOSStub_9988 {
  strings:
    $key_9988 = { cd e0 [2] b9 f8 [2] fe fa [2] b9 eb [2] f7 e7 [2] fb ed [2] ec e6 [2] f7 a8 [2] ca }

  condition:
    any of them
}