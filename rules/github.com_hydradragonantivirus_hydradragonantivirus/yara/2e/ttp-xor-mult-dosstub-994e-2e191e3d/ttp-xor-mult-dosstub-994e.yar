rule TTP_XOR_MULT_DOSStub_994e {
  strings:
    $key_994e = { cd 26 [2] b9 3e [2] fe 3c [2] b9 2d [2] f7 21 [2] fb 2b [2] ec 20 [2] f7 6e [2] ca }

  condition:
    any of them
}