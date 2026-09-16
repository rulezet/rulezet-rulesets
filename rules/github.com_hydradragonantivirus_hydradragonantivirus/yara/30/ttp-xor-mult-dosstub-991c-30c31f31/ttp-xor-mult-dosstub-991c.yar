rule TTP_XOR_MULT_DOSStub_991c {
  strings:
    $key_991c = { cd 74 [2] b9 6c [2] fe 6e [2] b9 7f [2] f7 73 [2] fb 79 [2] ec 72 [2] f7 3c [2] ca }

  condition:
    any of them
}