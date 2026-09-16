rule TTP_XOR_MULT_DOSStub_992d {
  strings:
    $key_992d = { cd 45 [2] b9 5d [2] fe 5f [2] b9 4e [2] f7 42 [2] fb 48 [2] ec 43 [2] f7 0d [2] ca }

  condition:
    any of them
}