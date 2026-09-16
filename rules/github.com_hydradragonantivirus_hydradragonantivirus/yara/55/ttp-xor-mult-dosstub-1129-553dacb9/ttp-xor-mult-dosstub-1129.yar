rule TTP_XOR_MULT_DOSStub_1129 {
  strings:
    $key_1129 = { 45 41 [2] 31 59 [2] 76 5b [2] 31 4a [2] 7f 46 [2] 73 4c [2] 64 47 [2] 7f 09 [2] 42 }

  condition:
    any of them
}