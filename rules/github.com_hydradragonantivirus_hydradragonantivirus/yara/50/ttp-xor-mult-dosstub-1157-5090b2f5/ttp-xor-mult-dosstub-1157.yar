rule TTP_XOR_MULT_DOSStub_1157 {
  strings:
    $key_1157 = { 45 3f [2] 31 27 [2] 76 25 [2] 31 34 [2] 7f 38 [2] 73 32 [2] 64 39 [2] 7f 77 [2] 42 }

  condition:
    any of them
}