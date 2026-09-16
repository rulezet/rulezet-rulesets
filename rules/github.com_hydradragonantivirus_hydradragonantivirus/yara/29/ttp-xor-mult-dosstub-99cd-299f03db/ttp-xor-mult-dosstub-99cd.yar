rule TTP_XOR_MULT_DOSStub_99cd {
  strings:
    $key_99cd = { cd a5 [2] b9 bd [2] fe bf [2] b9 ae [2] f7 a2 [2] fb a8 [2] ec a3 [2] f7 ed [2] ca }

  condition:
    any of them
}