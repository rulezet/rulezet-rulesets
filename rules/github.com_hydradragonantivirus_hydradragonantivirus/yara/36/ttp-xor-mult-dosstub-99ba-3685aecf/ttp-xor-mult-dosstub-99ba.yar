rule TTP_XOR_MULT_DOSStub_99ba {
  strings:
    $key_99ba = { cd d2 [2] b9 ca [2] fe c8 [2] b9 d9 [2] f7 d5 [2] fb df [2] ec d4 [2] f7 9a [2] ca }

  condition:
    any of them
}