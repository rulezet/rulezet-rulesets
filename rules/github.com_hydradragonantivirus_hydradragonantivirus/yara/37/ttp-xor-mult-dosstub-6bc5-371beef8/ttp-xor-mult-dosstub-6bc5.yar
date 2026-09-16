rule TTP_XOR_MULT_DOSStub_6bc5 {
  strings:
    $key_6bc5 = { 3f ad [2] 4b b5 [2] 0c b7 [2] 4b a6 [2] 05 aa [2] 09 a0 [2] 1e ab [2] 05 e5 [2] 38 }

  condition:
    any of them
}