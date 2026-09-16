rule TTP_XOR_MULT_DOSStub_1178 {
  strings:
    $key_1178 = { 45 10 [2] 31 08 [2] 76 0a [2] 31 1b [2] 7f 17 [2] 73 1d [2] 64 16 [2] 7f 58 [2] 42 }

  condition:
    any of them
}