rule TTP_XOR_MULT_DOSStub_1174 {
  strings:
    $key_1174 = { 45 1c [2] 31 04 [2] 76 06 [2] 31 17 [2] 7f 1b [2] 73 11 [2] 64 1a [2] 7f 54 [2] 42 }

  condition:
    any of them
}