rule TTP_XOR_MULT_DOSStub_d9cf {
  strings:
    $key_d9cf = { 8d a7 [2] f9 bf [2] be bd [2] f9 ac [2] b7 a0 [2] bb aa [2] ac a1 [2] b7 ef [2] 8a }

  condition:
    any of them
}