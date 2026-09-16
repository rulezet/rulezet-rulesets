rule TTP_XOR_MULT_DOSStub_56cd {
  strings:
    $key_56cd = { 02 a5 [2] 76 bd [2] 31 bf [2] 76 ae [2] 38 a2 [2] 34 a8 [2] 23 a3 [2] 38 ed [2] 05 }

  condition:
    any of them
}