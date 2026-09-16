rule TTP_XOR_MULT_DOSStub_1b28 {
  strings:
    $key_1b28 = { 4f 40 [2] 3b 58 [2] 7c 5a [2] 3b 4b [2] 75 47 [2] 79 4d [2] 6e 46 [2] 75 08 [2] 48 }

  condition:
    any of them
}