rule TTP_XOR_MULT_DOSStub_f7cd {
  strings:
    $key_f7cd = { a3 a5 [2] d7 bd [2] 90 bf [2] d7 ae [2] 99 a2 [2] 95 a8 [2] 82 a3 [2] 99 ed [2] a4 }

  condition:
    any of them
}