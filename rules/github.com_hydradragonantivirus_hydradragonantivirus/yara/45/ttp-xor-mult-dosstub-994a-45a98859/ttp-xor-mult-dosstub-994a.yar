rule TTP_XOR_MULT_DOSStub_994a {
  strings:
    $key_994a = { cd 22 [2] b9 3a [2] fe 38 [2] b9 29 [2] f7 25 [2] fb 2f [2] ec 24 [2] f7 6a [2] ca }

  condition:
    any of them
}