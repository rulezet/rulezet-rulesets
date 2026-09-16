rule TTP_XOR_MULT_DOSStub_14cd {
  strings:
    $key_14cd = { 40 a5 [2] 34 bd [2] 73 bf [2] 34 ae [2] 7a a2 [2] 76 a8 [2] 61 a3 [2] 7a ed [2] 47 }

  condition:
    any of them
}