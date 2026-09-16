rule TTP_XOR_MULT_DOSStub_a8cf {
  strings:
    $key_a8cf = { fc a7 [2] 88 bf [2] cf bd [2] 88 ac [2] c6 a0 [2] ca aa [2] dd a1 [2] c6 ef [2] fb }

  condition:
    any of them
}