rule TTP_XOR_MULT_DOSStub_c1cd {
  strings:
    $key_c1cd = { 95 a5 [2] e1 bd [2] a6 bf [2] e1 ae [2] af a2 [2] a3 a8 [2] b4 a3 [2] af ed [2] 92 }

  condition:
    any of them
}