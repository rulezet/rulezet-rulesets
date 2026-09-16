rule TTP_XOR_MULT_DOSStub_1122 {
  strings:
    $key_1122 = { 45 4a [2] 31 52 [2] 76 50 [2] 31 41 [2] 7f 4d [2] 73 47 [2] 64 4c [2] 7f 02 [2] 42 }

  condition:
    any of them
}