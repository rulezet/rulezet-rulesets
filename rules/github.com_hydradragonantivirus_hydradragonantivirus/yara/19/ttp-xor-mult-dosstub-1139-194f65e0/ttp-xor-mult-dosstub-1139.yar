rule TTP_XOR_MULT_DOSStub_1139 {
  strings:
    $key_1139 = { 45 51 [2] 31 49 [2] 76 4b [2] 31 5a [2] 7f 56 [2] 73 5c [2] 64 57 [2] 7f 19 [2] 42 }

  condition:
    any of them
}