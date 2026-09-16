rule TTP_XOR_MULT_DOSStub_29c8 {
  strings:
    $key_29c8 = { 7d a0 [2] 09 b8 [2] 4e ba [2] 09 ab [2] 47 a7 [2] 4b ad [2] 5c a6 [2] 47 e8 [2] 7a }

  condition:
    any of them
}