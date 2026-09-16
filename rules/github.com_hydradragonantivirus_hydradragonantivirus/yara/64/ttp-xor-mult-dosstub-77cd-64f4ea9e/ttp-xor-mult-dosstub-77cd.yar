rule TTP_XOR_MULT_DOSStub_77cd {
  strings:
    $key_77cd = { 23 a5 [2] 57 bd [2] 10 bf [2] 57 ae [2] 19 a2 [2] 15 a8 [2] 02 a3 [2] 19 ed [2] 24 }

  condition:
    any of them
}