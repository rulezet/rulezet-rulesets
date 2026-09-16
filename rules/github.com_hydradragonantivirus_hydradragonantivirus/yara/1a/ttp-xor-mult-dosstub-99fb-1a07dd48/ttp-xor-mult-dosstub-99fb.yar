rule TTP_XOR_MULT_DOSStub_99fb {
  strings:
    $key_99fb = { cd 93 [2] b9 8b [2] fe 89 [2] b9 98 [2] f7 94 [2] fb 9e [2] ec 95 [2] f7 db [2] ca }

  condition:
    any of them
}