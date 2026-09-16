rule TTP_XOR_MULT_DOSStub_0b38 {
  strings:
    $key_0b38 = { 5f 50 [2] 2b 48 [2] 6c 4a [2] 2b 5b [2] 65 57 [2] 69 5d [2] 7e 56 [2] 65 18 [2] 58 }

  condition:
    any of them
}