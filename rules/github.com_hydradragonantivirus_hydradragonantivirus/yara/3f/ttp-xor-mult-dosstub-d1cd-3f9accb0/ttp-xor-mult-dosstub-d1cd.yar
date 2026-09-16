rule TTP_XOR_MULT_DOSStub_d1cd {
  strings:
    $key_d1cd = { 85 a5 [2] f1 bd [2] b6 bf [2] f1 ae [2] bf a2 [2] b3 a8 [2] a4 a3 [2] bf ed [2] 82 }

  condition:
    any of them
}