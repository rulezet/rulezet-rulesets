rule TTP_XOR_MULT_DOSStub_e3cd {
  strings:
    $key_e3cd = { b7 a5 [2] c3 bd [2] 84 bf [2] c3 ae [2] 8d a2 [2] 81 a8 [2] 96 a3 [2] 8d ed [2] b0 }

  condition:
    any of them
}