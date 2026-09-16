rule TTP_XOR_MULT_DOSStub_11cd {
  strings:
    $key_11cd = { 45 a5 [2] 31 bd [2] 76 bf [2] 31 ae [2] 7f a2 [2] 73 a8 [2] 64 a3 [2] 7f ed [2] 42 }

  condition:
    any of them
}