rule TTP_XOR_MULT_DOSStub_99da {
  strings:
    $key_99da = { cd b2 [2] b9 aa [2] fe a8 [2] b9 b9 [2] f7 b5 [2] fb bf [2] ec b4 [2] f7 fa [2] ca }

  condition:
    any of them
}