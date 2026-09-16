rule TTP_XOR_MULT_DOSStub_33cd {
  strings:
    $key_33cd = { 67 a5 [2] 13 bd [2] 54 bf [2] 13 ae [2] 5d a2 [2] 51 a8 [2] 46 a3 [2] 5d ed [2] 60 }

  condition:
    any of them
}