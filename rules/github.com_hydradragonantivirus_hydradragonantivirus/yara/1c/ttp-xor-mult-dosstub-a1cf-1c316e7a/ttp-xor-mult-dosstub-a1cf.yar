rule TTP_XOR_MULT_DOSStub_a1cf {
  strings:
    $key_a1cf = { f5 a7 [2] 81 bf [2] c6 bd [2] 81 ac [2] cf a0 [2] c3 aa [2] d4 a1 [2] cf ef [2] f2 }

  condition:
    any of them
}