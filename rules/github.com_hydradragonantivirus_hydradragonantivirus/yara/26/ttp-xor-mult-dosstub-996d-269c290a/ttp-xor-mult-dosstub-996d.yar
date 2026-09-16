rule TTP_XOR_MULT_DOSStub_996d {
  strings:
    $key_996d = { cd 05 [2] b9 1d [2] fe 1f [2] b9 0e [2] f7 02 [2] fb 08 [2] ec 03 [2] f7 4d [2] ca }

  condition:
    any of them
}