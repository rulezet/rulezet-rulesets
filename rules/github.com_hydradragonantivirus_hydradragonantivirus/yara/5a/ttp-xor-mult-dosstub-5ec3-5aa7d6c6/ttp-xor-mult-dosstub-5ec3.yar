rule TTP_XOR_MULT_DOSStub_5ec3 {
  strings:
    $key_5ec3 = { 0a ab [2] 7e b3 [2] 39 b1 [2] 7e a0 [2] 30 ac [2] 3c a6 [2] 2b ad [2] 30 e3 [2] 0d }

  condition:
    any of them
}