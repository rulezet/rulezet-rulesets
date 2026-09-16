rule TTP_XOR_MULT_DOSStub_62cd {
  strings:
    $key_62cd = { 36 a5 [2] 42 bd [2] 05 bf [2] 42 ae [2] 0c a2 [2] 00 a8 [2] 17 a3 [2] 0c ed [2] 31 }

  condition:
    any of them
}