rule TTP_XOR_MULT_DOSStub_3038 {
  strings:
    $key_3038 = { 64 50 [2] 10 48 [2] 57 4a [2] 10 5b [2] 5e 57 [2] 52 5d [2] 45 56 [2] 5e 18 [2] 63 }

  condition:
    any of them
}