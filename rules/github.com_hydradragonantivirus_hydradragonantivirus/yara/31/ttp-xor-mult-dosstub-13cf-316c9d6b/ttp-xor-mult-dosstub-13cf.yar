rule TTP_XOR_MULT_DOSStub_13cf {
  strings:
    $key_13cf = { 47 a7 [2] 33 bf [2] 74 bd [2] 33 ac [2] 7d a0 [2] 71 aa [2] 66 a1 [2] 7d ef [2] 40 }

  condition:
    any of them
}