rule TTP_XOR_MULT_DOSStub_999e {
  strings:
    $key_999e = { cd f6 [2] b9 ee [2] fe ec [2] b9 fd [2] f7 f1 [2] fb fb [2] ec f0 [2] f7 be [2] ca }

  condition:
    any of them
}