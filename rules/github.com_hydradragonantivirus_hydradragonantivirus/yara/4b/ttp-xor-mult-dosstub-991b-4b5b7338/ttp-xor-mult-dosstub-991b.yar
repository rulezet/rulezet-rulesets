rule TTP_XOR_MULT_DOSStub_991b {
  strings:
    $key_991b = { cd 73 [2] b9 6b [2] fe 69 [2] b9 78 [2] f7 74 [2] fb 7e [2] ec 75 [2] f7 3b [2] ca }

  condition:
    any of them
}