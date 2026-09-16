rule TTP_XOR_MULT_DOSStub_7ec3 {
  strings:
    $key_7ec3 = { 2a ab [2] 5e b3 [2] 19 b1 [2] 5e a0 [2] 10 ac [2] 1c a6 [2] 0b ad [2] 10 e3 [2] 2d }

  condition:
    any of them
}