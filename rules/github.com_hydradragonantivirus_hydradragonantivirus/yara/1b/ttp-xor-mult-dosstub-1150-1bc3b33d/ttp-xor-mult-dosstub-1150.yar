rule TTP_XOR_MULT_DOSStub_1150 {
  strings:
    $key_1150 = { 45 38 [2] 31 20 [2] 76 22 [2] 31 33 [2] 7f 3f [2] 73 35 [2] 64 3e [2] 7f 70 [2] 42 }

  condition:
    any of them
}