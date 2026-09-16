rule TTP_XOR_MULT_DOSStub_4b38 {
  strings:
    $key_4b38 = { 1f 50 [2] 6b 48 [2] 2c 4a [2] 6b 5b [2] 25 57 [2] 29 5d [2] 3e 56 [2] 25 18 [2] 18 }

  condition:
    any of them
}