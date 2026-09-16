rule TTP_XOR_MULT_DOSStub_a7cd {
  strings:
    $key_a7cd = { f3 a5 [2] 87 bd [2] c0 bf [2] 87 ae [2] c9 a2 [2] c5 a8 [2] d2 a3 [2] c9 ed [2] f4 }

  condition:
    any of them
}