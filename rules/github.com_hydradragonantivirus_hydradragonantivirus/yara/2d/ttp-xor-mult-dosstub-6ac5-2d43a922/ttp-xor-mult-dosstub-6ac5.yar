rule TTP_XOR_MULT_DOSStub_6ac5 {
  strings:
    $key_6ac5 = { 3e ad [2] 4a b5 [2] 0d b7 [2] 4a a6 [2] 04 aa [2] 08 a0 [2] 1f ab [2] 04 e5 [2] 39 }

  condition:
    any of them
}