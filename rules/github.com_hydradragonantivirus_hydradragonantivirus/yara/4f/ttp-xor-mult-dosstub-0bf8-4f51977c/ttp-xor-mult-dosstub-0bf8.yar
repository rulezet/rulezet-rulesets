rule TTP_XOR_MULT_DOSStub_0bf8 {
  strings:
    $key_0bf8 = { 5f 90 [2] 2b 88 [2] 6c 8a [2] 2b 9b [2] 65 97 [2] 69 9d [2] 7e 96 [2] 65 d8 [2] 58 }

  condition:
    any of them
}