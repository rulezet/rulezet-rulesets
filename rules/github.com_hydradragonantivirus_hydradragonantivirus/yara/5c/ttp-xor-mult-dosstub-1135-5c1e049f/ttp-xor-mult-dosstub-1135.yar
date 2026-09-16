rule TTP_XOR_MULT_DOSStub_1135 {
  strings:
    $key_1135 = { 45 5d [2] 31 45 [2] 76 47 [2] 31 56 [2] 7f 5a [2] 73 50 [2] 64 5b [2] 7f 15 [2] 42 }

  condition:
    any of them
}