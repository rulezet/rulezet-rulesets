rule TTP_XOR_MULT_DOSStub_1151 {
  strings:
    $key_1151 = { 45 39 [2] 31 21 [2] 76 23 [2] 31 32 [2] 7f 3e [2] 73 34 [2] 64 3f [2] 7f 71 [2] 42 }

  condition:
    any of them
}