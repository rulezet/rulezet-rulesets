rule TTP_XOR_MULT_DOSStub_99ea {
  strings:
    $key_99ea = { cd 82 [2] b9 9a [2] fe 98 [2] b9 89 [2] f7 85 [2] fb 8f [2] ec 84 [2] f7 ca [2] ca }

  condition:
    any of them
}