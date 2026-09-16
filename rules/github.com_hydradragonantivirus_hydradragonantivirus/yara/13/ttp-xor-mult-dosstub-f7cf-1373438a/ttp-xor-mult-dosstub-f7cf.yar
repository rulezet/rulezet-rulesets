rule TTP_XOR_MULT_DOSStub_f7cf {
  strings:
    $key_f7cf = { a3 a7 [2] d7 bf [2] 90 bd [2] d7 ac [2] 99 a0 [2] 95 aa [2] 82 a1 [2] 99 ef [2] a4 }

  condition:
    any of them
}