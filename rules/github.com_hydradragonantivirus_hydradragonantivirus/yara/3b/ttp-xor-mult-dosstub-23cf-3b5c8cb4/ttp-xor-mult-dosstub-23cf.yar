rule TTP_XOR_MULT_DOSStub_23cf {
  strings:
    $key_23cf = { 77 a7 [2] 03 bf [2] 44 bd [2] 03 ac [2] 4d a0 [2] 41 aa [2] 56 a1 [2] 4d ef [2] 70 }

  condition:
    any of them
}