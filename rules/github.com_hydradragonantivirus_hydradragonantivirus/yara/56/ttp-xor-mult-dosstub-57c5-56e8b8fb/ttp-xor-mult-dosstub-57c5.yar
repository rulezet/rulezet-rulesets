rule TTP_XOR_MULT_DOSStub_57c5 {
  strings:
    $key_57c5 = { 03 ad [2] 77 b5 [2] 30 b7 [2] 77 a6 [2] 39 aa [2] 35 a0 [2] 22 ab [2] 39 e5 [2] 04 }

  condition:
    any of them
}