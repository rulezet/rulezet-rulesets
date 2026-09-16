rule TTP_XOR_MULT_DOSStub_37cf {
  strings:
    $key_37cf = { 63 a7 [2] 17 bf [2] 50 bd [2] 17 ac [2] 59 a0 [2] 55 aa [2] 42 a1 [2] 59 ef [2] 64 }

  condition:
    any of them
}