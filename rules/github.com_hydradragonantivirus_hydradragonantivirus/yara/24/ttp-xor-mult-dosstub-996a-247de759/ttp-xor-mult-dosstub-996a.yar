rule TTP_XOR_MULT_DOSStub_996a {
  strings:
    $key_996a = { cd 02 [2] b9 1a [2] fe 18 [2] b9 09 [2] f7 05 [2] fb 0f [2] ec 04 [2] f7 4a [2] ca }

  condition:
    any of them
}