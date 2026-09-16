rule TTP_XOR_MULT_DOSStub_65c2 {
  strings:
    $key_65c2 = { 31 aa [2] 45 b2 [2] 02 b0 [2] 45 a1 [2] 0b ad [2] 07 a7 [2] 10 ac [2] 0b e2 [2] 36 }

  condition:
    any of them
}