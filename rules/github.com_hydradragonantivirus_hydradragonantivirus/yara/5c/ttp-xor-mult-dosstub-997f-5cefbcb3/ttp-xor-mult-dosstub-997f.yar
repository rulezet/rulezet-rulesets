rule TTP_XOR_MULT_DOSStub_997f {
  strings:
    $key_997f = { cd 17 [2] b9 0f [2] fe 0d [2] b9 1c [2] f7 10 [2] fb 1a [2] ec 11 [2] f7 5f [2] ca }

  condition:
    any of them
}