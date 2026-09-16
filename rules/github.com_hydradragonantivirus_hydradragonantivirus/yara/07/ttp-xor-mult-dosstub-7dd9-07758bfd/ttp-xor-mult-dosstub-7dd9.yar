rule TTP_XOR_MULT_DOSStub_7dd9 {
  strings:
    $key_7dd9 = { 29 b1 [2] 5d a9 [2] 1a ab [2] 5d ba [2] 13 b6 [2] 1f bc [2] 08 b7 [2] 13 f9 [2] 2e }

  condition:
    any of them
}