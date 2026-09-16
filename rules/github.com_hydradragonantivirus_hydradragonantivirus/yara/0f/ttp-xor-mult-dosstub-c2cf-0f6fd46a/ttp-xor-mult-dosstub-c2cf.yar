rule TTP_XOR_MULT_DOSStub_c2cf {
  strings:
    $key_c2cf = { 96 a7 [2] e2 bf [2] a5 bd [2] e2 ac [2] ac a0 [2] a0 aa [2] b7 a1 [2] ac ef [2] 91 }

  condition:
    any of them
}