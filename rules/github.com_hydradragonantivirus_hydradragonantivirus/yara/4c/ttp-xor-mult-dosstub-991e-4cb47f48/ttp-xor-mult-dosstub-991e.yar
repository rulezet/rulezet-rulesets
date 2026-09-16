rule TTP_XOR_MULT_DOSStub_991e {
  strings:
    $key_991e = { cd 76 [2] b9 6e [2] fe 6c [2] b9 7d [2] f7 71 [2] fb 7b [2] ec 70 [2] f7 3e [2] ca }

  condition:
    any of them
}