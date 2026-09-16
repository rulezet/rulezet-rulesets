rule TTP_XOR_MULT_DOSStub_c4cf {
  strings:
    $key_c4cf = { 90 a7 [2] e4 bf [2] a3 bd [2] e4 ac [2] aa a0 [2] a6 aa [2] b1 a1 [2] aa ef [2] 97 }

  condition:
    any of them
}