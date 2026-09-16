rule TTP_XOR_MULT_DOSStub_99fe {
  strings:
    $key_99fe = { cd 96 [2] b9 8e [2] fe 8c [2] b9 9d [2] f7 91 [2] fb 9b [2] ec 90 [2] f7 de [2] ca }

  condition:
    any of them
}