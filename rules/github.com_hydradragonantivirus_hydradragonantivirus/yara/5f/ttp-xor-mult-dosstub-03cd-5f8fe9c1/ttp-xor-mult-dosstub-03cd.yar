rule TTP_XOR_MULT_DOSStub_03cd {
  strings:
    $key_03cd = { 57 a5 [2] 23 bd [2] 64 bf [2] 23 ae [2] 6d a2 [2] 61 a8 [2] 76 a3 [2] 6d ed [2] 50 }

  condition:
    any of them
}