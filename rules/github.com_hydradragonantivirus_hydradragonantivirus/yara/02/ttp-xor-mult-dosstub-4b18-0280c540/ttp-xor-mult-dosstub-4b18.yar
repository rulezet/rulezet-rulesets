rule TTP_XOR_MULT_DOSStub_4b18 {
  strings:
    $key_4b18 = { 1f 70 [2] 6b 68 [2] 2c 6a [2] 6b 7b [2] 25 77 [2] 29 7d [2] 3e 76 [2] 25 38 [2] 18 }

  condition:
    any of them
}