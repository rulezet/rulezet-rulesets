rule TTP_XOR_MULT_DOSStub_a8c9 {
  strings:
    $key_a8c9 = { fc a1 [2] 88 b9 [2] cf bb [2] 88 aa [2] c6 a6 [2] ca ac [2] dd a7 [2] c6 e9 [2] fb }

  condition:
    any of them
}