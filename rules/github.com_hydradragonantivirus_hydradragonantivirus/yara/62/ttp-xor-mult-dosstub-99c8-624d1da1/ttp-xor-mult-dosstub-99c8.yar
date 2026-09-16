rule TTP_XOR_MULT_DOSStub_99c8 {
  strings:
    $key_99c8 = { cd a0 [2] b9 b8 [2] fe ba [2] b9 ab [2] f7 a7 [2] fb ad [2] ec a6 [2] f7 e8 [2] ca }

  condition:
    any of them
}