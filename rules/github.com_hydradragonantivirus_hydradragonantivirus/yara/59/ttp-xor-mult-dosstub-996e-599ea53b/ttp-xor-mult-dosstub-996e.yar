rule TTP_XOR_MULT_DOSStub_996e {
  strings:
    $key_996e = { cd 06 [2] b9 1e [2] fe 1c [2] b9 0d [2] f7 01 [2] fb 0b [2] ec 00 [2] f7 4e [2] ca }

  condition:
    any of them
}