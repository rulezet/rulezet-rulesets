rule TTP_XOR_MULT_DOSStub_9985 {
  strings:
    $key_9985 = { cd ed [2] b9 f5 [2] fe f7 [2] b9 e6 [2] f7 ea [2] fb e0 [2] ec eb [2] f7 a5 [2] ca }

  condition:
    any of them
}