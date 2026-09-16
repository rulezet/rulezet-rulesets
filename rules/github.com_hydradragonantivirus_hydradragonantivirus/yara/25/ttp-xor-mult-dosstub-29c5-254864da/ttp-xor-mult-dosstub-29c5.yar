rule TTP_XOR_MULT_DOSStub_29c5 {
  strings:
    $key_29c5 = { 7d ad [2] 09 b5 [2] 4e b7 [2] 09 a6 [2] 47 aa [2] 4b a0 [2] 5c ab [2] 47 e5 [2] 7a }

  condition:
    any of them
}