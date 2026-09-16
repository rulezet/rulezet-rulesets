rule TTP_XOR_MULT_DOSStub_9992 {
  strings:
    $key_9992 = { cd fa [2] b9 e2 [2] fe e0 [2] b9 f1 [2] f7 fd [2] fb f7 [2] ec fc [2] f7 b2 [2] ca }

  condition:
    any of them
}