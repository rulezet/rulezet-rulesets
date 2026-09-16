rule TTP_XOR_MULT_DOSStub_994b {
  strings:
    $key_994b = { cd 23 [2] b9 3b [2] fe 39 [2] b9 28 [2] f7 24 [2] fb 2e [2] ec 25 [2] f7 6b [2] ca }

  condition:
    any of them
}