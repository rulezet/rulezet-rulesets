rule TTP_XOR_MULT_DOSStub_07c5 {
  strings:
    $key_07c5 = { 53 ad [2] 27 b5 [2] 60 b7 [2] 27 a6 [2] 69 aa [2] 65 a0 [2] 72 ab [2] 69 e5 [2] 54 }

  condition:
    any of them
}