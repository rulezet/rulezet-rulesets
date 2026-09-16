rule TTP_XOR_MULT_DOSStub_72cd {
  strings:
    $key_72cd = { 26 a5 [2] 52 bd [2] 15 bf [2] 52 ae [2] 1c a2 [2] 10 a8 [2] 07 a3 [2] 1c ed [2] 21 }

  condition:
    any of them
}