rule TTP_XOR_MULT_DOSStub_b4cd {
  strings:
    $key_b4cd = { e0 a5 [2] 94 bd [2] d3 bf [2] 94 ae [2] da a2 [2] d6 a8 [2] c1 a3 [2] da ed [2] e7 }

  condition:
    any of them
}