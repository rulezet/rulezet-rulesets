rule TTP_XOR_MULT_DOSStub_999b {
  strings:
    $key_999b = { cd f3 [2] b9 eb [2] fe e9 [2] b9 f8 [2] f7 f4 [2] fb fe [2] ec f5 [2] f7 bb [2] ca }

  condition:
    any of them
}