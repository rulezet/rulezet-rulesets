rule TTP_XOR_MULT_DOSStub_994c {
  strings:
    $key_994c = { cd 24 [2] b9 3c [2] fe 3e [2] b9 2f [2] f7 23 [2] fb 29 [2] ec 22 [2] f7 6c [2] ca }

  condition:
    any of them
}