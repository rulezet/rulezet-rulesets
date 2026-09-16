rule TTP_XOR_MULT_DOSStub_e2cd {
  strings:
    $key_e2cd = { b6 a5 [2] c2 bd [2] 85 bf [2] c2 ae [2] 8c a2 [2] 80 a8 [2] 97 a3 [2] 8c ed [2] b1 }

  condition:
    any of them
}