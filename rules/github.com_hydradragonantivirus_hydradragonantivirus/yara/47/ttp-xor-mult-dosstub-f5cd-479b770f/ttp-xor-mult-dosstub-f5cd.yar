rule TTP_XOR_MULT_DOSStub_f5cd {
  strings:
    $key_f5cd = { a1 a5 [2] d5 bd [2] 92 bf [2] d5 ae [2] 9b a2 [2] 97 a8 [2] 80 a3 [2] 9b ed [2] a6 }

  condition:
    any of them
}