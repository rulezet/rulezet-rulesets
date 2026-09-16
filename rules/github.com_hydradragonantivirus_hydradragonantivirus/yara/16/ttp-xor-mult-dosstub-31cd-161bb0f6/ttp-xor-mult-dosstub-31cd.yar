rule TTP_XOR_MULT_DOSStub_31cd {
  strings:
    $key_31cd = { 65 a5 [2] 11 bd [2] 56 bf [2] 11 ae [2] 5f a2 [2] 53 a8 [2] 44 a3 [2] 5f ed [2] 62 }

  condition:
    any of them
}