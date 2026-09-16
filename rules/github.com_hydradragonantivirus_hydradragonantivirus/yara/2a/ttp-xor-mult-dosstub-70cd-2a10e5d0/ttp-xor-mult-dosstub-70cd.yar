rule TTP_XOR_MULT_DOSStub_70cd {
  strings:
    $key_70cd = { 24 a5 [2] 50 bd [2] 17 bf [2] 50 ae [2] 1e a2 [2] 12 a8 [2] 05 a3 [2] 1e ed [2] 23 }

  condition:
    any of them
}