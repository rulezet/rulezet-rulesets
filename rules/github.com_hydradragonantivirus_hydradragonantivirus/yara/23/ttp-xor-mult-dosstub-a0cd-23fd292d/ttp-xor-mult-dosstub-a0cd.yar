rule TTP_XOR_MULT_DOSStub_a0cd {
  strings:
    $key_a0cd = { f4 a5 [2] 80 bd [2] c7 bf [2] 80 ae [2] ce a2 [2] c2 a8 [2] d5 a3 [2] ce ed [2] f3 }

  condition:
    any of them
}