rule TTP_XOR_MULT_DOSStub_9999 {
  strings:
    $key_9999 = { cd f1 [2] b9 e9 [2] fe eb [2] b9 fa [2] f7 f6 [2] fb fc [2] ec f7 [2] f7 b9 [2] ca }

  condition:
    any of them
}