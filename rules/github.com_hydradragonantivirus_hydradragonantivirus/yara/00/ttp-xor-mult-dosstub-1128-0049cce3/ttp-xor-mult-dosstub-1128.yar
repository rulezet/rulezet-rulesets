rule TTP_XOR_MULT_DOSStub_1128 {
  strings:
    $key_1128 = { 45 40 [2] 31 58 [2] 76 5a [2] 31 4b [2] 7f 47 [2] 73 4d [2] 64 46 [2] 7f 08 [2] 42 }

  condition:
    any of them
}