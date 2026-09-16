rule TTP_XOR_MULT_DOSStub_dd9c {
  strings:
    $key_dd9c = { 89 f4 [2] fd ec [2] ba ee [2] fd ff [2] b3 f3 [2] bf f9 [2] a8 f2 [2] b3 bc [2] 8e }

  condition:
    any of them
}