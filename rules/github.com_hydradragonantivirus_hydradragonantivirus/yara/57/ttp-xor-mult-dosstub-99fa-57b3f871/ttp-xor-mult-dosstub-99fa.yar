rule TTP_XOR_MULT_DOSStub_99fa {
  strings:
    $key_99fa = { cd 92 [2] b9 8a [2] fe 88 [2] b9 99 [2] f7 95 [2] fb 9f [2] ec 94 [2] f7 da [2] ca }

  condition:
    any of them
}