rule TTP_XOR_MULT_DOSStub_d7cd {
  strings:
    $key_d7cd = { 83 a5 [2] f7 bd [2] b0 bf [2] f7 ae [2] b9 a2 [2] b5 a8 [2] a2 a3 [2] b9 ed [2] 84 }

  condition:
    any of them
}