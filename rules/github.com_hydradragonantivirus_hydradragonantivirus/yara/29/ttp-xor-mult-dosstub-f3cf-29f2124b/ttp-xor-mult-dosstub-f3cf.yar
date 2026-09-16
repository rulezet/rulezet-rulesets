rule TTP_XOR_MULT_DOSStub_f3cf {
  strings:
    $key_f3cf = { a7 a7 [2] d3 bf [2] 94 bd [2] d3 ac [2] 9d a0 [2] 91 aa [2] 86 a1 [2] 9d ef [2] a0 }

  condition:
    any of them
}