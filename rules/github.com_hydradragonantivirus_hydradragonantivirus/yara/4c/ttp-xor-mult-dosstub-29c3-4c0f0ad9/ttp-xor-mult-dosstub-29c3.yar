rule TTP_XOR_MULT_DOSStub_29c3 {
  strings:
    $key_29c3 = { 7d ab [2] 09 b3 [2] 4e b1 [2] 09 a0 [2] 47 ac [2] 4b a6 [2] 5c ad [2] 47 e3 [2] 7a }

  condition:
    any of them
}