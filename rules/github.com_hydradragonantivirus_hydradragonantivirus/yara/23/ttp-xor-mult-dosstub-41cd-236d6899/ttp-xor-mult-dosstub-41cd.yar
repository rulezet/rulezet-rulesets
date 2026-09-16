rule TTP_XOR_MULT_DOSStub_41cd {
  strings:
    $key_41cd = { 15 a5 [2] 61 bd [2] 26 bf [2] 61 ae [2] 2f a2 [2] 23 a8 [2] 34 a3 [2] 2f ed [2] 12 }

  condition:
    any of them
}