rule TTP_XOR_MULT_DOSStub_b1cd {
  strings:
    $key_b1cd = { e5 a5 [2] 91 bd [2] d6 bf [2] 91 ae [2] df a2 [2] d3 a8 [2] c4 a3 [2] df ed [2] e2 }

  condition:
    any of them
}