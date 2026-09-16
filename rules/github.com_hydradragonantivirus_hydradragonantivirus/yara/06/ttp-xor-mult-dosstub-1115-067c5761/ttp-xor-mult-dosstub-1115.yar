rule TTP_XOR_MULT_DOSStub_1115 {
  strings:
    $key_1115 = { 45 7d [2] 31 65 [2] 76 67 [2] 31 76 [2] 7f 7a [2] 73 70 [2] 64 7b [2] 7f 35 [2] 42 }

  condition:
    any of them
}