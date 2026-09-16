rule TTP_XOR_MULT_DOSStub_0b15 {
  strings:
    $key_0b15 = { 5f 7d [2] 2b 65 [2] 6c 67 [2] 2b 76 [2] 65 7a [2] 69 70 [2] 7e 7b [2] 65 35 [2] 58 }

  condition:
    any of them
}