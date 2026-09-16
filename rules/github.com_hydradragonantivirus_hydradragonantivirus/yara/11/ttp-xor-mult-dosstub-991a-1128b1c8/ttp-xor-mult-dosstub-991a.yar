rule TTP_XOR_MULT_DOSStub_991a {
  strings:
    $key_991a = { cd 72 [2] b9 6a [2] fe 68 [2] b9 79 [2] f7 75 [2] fb 7f [2] ec 74 [2] f7 3a [2] ca }

  condition:
    any of them
}