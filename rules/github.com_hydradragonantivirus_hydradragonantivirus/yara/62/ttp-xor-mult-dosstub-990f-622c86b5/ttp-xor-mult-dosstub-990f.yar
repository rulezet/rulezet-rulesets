rule TTP_XOR_MULT_DOSStub_990f {
  strings:
    $key_990f = { cd 67 [2] b9 7f [2] fe 7d [2] b9 6c [2] f7 60 [2] fb 6a [2] ec 61 [2] f7 2f [2] ca }

  condition:
    any of them
}