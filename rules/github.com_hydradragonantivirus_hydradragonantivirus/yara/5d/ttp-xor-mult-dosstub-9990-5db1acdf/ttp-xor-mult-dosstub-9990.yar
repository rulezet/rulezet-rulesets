rule TTP_XOR_MULT_DOSStub_9990 {
  strings:
    $key_9990 = { cd f8 [2] b9 e0 [2] fe e2 [2] b9 f3 [2] f7 ff [2] fb f5 [2] ec fe [2] f7 b0 [2] ca }

  condition:
    any of them
}