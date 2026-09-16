rule TTP_XOR_MULT_DOSStub_40cd {
  strings:
    $key_40cd = { 14 a5 [2] 60 bd [2] 27 bf [2] 60 ae [2] 2e a2 [2] 22 a8 [2] 35 a3 [2] 2e ed [2] 13 }

  condition:
    any of them
}