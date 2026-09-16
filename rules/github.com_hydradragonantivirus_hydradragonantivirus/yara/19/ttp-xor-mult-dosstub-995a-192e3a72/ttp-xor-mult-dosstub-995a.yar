rule TTP_XOR_MULT_DOSStub_995a {
  strings:
    $key_995a = { cd 32 [2] b9 2a [2] fe 28 [2] b9 39 [2] f7 35 [2] fb 3f [2] ec 34 [2] f7 7a [2] ca }

  condition:
    any of them
}