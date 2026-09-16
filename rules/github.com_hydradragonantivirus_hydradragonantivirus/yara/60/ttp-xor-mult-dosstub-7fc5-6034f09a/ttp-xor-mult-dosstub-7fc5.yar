rule TTP_XOR_MULT_DOSStub_7fc5 {
  strings:
    $key_7fc5 = { 2b ad [2] 5f b5 [2] 18 b7 [2] 5f a6 [2] 11 aa [2] 1d a0 [2] 0a ab [2] 11 e5 [2] 2c }

  condition:
    any of them
}