rule TTP_XOR_MULT_DOSStub_99de {
  strings:
    $key_99de = { cd b6 [2] b9 ae [2] fe ac [2] b9 bd [2] f7 b1 [2] fb bb [2] ec b0 [2] f7 fe [2] ca }

  condition:
    any of them
}