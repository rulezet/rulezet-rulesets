rule TTP_XOR_MULT_DOSStub_9921 {
  strings:
    $key_9921 = { cd 49 [2] b9 51 [2] fe 53 [2] b9 42 [2] f7 4e [2] fb 44 [2] ec 4f [2] f7 01 [2] ca }

  condition:
    any of them
}