rule TTP_XOR_MULT_DOSStub_f4cd {
  strings:
    $key_f4cd = { a0 a5 [2] d4 bd [2] 93 bf [2] d4 ae [2] 9a a2 [2] 96 a8 [2] 81 a3 [2] 9a ed [2] a7 }

  condition:
    any of them
}