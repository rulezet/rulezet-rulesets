rule TTP_XOR_MULT_DOSStub_99af {
  strings:
    $key_99af = { cd c7 [2] b9 df [2] fe dd [2] b9 cc [2] f7 c0 [2] fb ca [2] ec c1 [2] f7 8f [2] ca }

  condition:
    any of them
}