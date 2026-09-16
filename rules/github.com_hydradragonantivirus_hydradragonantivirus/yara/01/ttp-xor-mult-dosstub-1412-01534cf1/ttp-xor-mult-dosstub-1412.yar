rule TTP_XOR_MULT_DOSStub_1412 {
  strings:
    $key_1412 = { 40 7a [2] 34 62 [2] 73 60 [2] 34 71 [2] 7a 7d [2] 76 77 [2] 61 7c [2] 7a 32 [2] 47 }

  condition:
    any of them
}