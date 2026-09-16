rule TTP_XOR_MULT_DOSStub_1105 {
  strings:
    $key_1105 = { 45 6d [2] 31 75 [2] 76 77 [2] 31 66 [2] 7f 6a [2] 73 60 [2] 64 6b [2] 7f 25 [2] 42 }

  condition:
    any of them
}