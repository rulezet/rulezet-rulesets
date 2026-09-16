rule TTP_XOR_MULT_DOSStub_10cf {
  strings:
    $key_10cf = { 44 a7 [2] 30 bf [2] 77 bd [2] 30 ac [2] 7e a0 [2] 72 aa [2] 65 a1 [2] 7e ef [2] 43 }

  condition:
    any of them
}