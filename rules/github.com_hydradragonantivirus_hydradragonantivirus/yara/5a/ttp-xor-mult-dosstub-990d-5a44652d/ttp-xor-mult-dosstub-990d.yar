rule TTP_XOR_MULT_DOSStub_990d {
  strings:
    $key_990d = { cd 65 [2] b9 7d [2] fe 7f [2] b9 6e [2] f7 62 [2] fb 68 [2] ec 63 [2] f7 2d [2] ca }

  condition:
    any of them
}