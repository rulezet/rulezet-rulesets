rule TTP_XOR_MULT_DOSStub_19d2 {
  strings:
    $key_19d2 = { 4d ba [2] 39 a2 [2] 7e a0 [2] 39 b1 [2] 77 bd [2] 7b b7 [2] 6c bc [2] 77 f2 [2] 4a }

  condition:
    any of them
}