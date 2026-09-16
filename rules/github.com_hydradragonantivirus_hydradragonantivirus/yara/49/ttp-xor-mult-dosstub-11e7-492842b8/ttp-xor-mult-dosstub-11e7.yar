rule TTP_XOR_MULT_DOSStub_11e7 {
  strings:
    $key_11e7 = { 45 8f [2] 31 97 [2] 76 95 [2] 31 84 [2] 7f 88 [2] 73 82 [2] 64 89 [2] 7f c7 [2] 42 }

  condition:
    any of them
}