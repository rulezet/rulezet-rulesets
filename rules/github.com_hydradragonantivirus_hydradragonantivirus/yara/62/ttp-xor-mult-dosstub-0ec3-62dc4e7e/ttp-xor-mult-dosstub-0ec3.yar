rule TTP_XOR_MULT_DOSStub_0ec3 {
  strings:
    $key_0ec3 = { 5a ab [2] 2e b3 [2] 69 b1 [2] 2e a0 [2] 60 ac [2] 6c a6 [2] 7b ad [2] 60 e3 [2] 5d }

  condition:
    any of them
}