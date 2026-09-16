rule TTP_XOR_MULT_DOSStub_51cd {
  strings:
    $key_51cd = { 05 a5 [2] 71 bd [2] 36 bf [2] 71 ae [2] 3f a2 [2] 33 a8 [2] 24 a3 [2] 3f ed [2] 02 }

  condition:
    any of them
}