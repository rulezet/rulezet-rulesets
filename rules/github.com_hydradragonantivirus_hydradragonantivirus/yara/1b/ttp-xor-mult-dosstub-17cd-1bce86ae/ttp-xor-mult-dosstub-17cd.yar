rule TTP_XOR_MULT_DOSStub_17cd {
  strings:
    $key_17cd = { 43 a5 [2] 37 bd [2] 70 bf [2] 37 ae [2] 79 a2 [2] 75 a8 [2] 62 a3 [2] 79 ed [2] 44 }

  condition:
    any of them
}