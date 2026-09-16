rule TTP_XOR_MULT_DOSStub_4b28 {
  strings:
    $key_4b28 = { 1f 40 [2] 6b 58 [2] 2c 5a [2] 6b 4b [2] 25 47 [2] 29 4d [2] 3e 46 [2] 25 08 [2] 18 }

  condition:
    any of them
}