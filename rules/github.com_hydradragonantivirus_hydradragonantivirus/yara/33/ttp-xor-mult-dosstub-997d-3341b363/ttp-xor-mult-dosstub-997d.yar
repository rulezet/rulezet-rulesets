rule TTP_XOR_MULT_DOSStub_997d {
  strings:
    $key_997d = { cd 15 [2] b9 0d [2] fe 0f [2] b9 1e [2] f7 12 [2] fb 18 [2] ec 13 [2] f7 5d [2] ca }

  condition:
    any of them
}