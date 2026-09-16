rule TTP_XOR_MULT_DOSStub_11cf {
  strings:
    $key_11cf = { 45 a7 [2] 31 bf [2] 76 bd [2] 31 ac [2] 7f a0 [2] 73 aa [2] 64 a1 [2] 7f ef [2] 42 }

  condition:
    any of them
}