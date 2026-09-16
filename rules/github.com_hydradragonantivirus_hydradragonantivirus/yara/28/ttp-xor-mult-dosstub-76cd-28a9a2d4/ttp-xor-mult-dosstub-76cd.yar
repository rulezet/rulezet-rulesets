rule TTP_XOR_MULT_DOSStub_76cd {
  strings:
    $key_76cd = { 22 a5 [2] 56 bd [2] 11 bf [2] 56 ae [2] 18 a2 [2] 14 a8 [2] 03 a3 [2] 18 ed [2] 25 }

  condition:
    any of them
}