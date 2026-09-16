rule TTP_XOR_MULT_DOSStub_3bc5 {
  strings:
    $key_3bc5 = { 6f ad [2] 1b b5 [2] 5c b7 [2] 1b a6 [2] 55 aa [2] 59 a0 [2] 4e ab [2] 55 e5 [2] 68 }

  condition:
    any of them
}