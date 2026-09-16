rule TTP_XOR_MULT_DOSStub_990a {
  strings:
    $key_990a = { cd 62 [2] b9 7a [2] fe 78 [2] b9 69 [2] f7 65 [2] fb 6f [2] ec 64 [2] f7 2a [2] ca }

  condition:
    any of them
}