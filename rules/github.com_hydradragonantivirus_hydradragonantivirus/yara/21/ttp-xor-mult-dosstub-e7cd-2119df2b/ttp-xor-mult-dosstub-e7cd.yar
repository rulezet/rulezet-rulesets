rule TTP_XOR_MULT_DOSStub_e7cd {
  strings:
    $key_e7cd = { b3 a5 [2] c7 bd [2] 80 bf [2] c7 ae [2] 89 a2 [2] 85 a8 [2] 92 a3 [2] 89 ed [2] b4 }

  condition:
    any of them
}