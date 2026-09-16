rule TTP_XOR_MULT_DOSStub_20cd {
  strings:
    $key_20cd = { 74 a5 [2] 00 bd [2] 47 bf [2] 00 ae [2] 4e a2 [2] 42 a8 [2] 55 a3 [2] 4e ed [2] 73 }

  condition:
    any of them
}