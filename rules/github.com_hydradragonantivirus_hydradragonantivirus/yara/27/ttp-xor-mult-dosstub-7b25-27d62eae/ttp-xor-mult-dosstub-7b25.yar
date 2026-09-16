rule TTP_XOR_MULT_DOSStub_7b25 {
  strings:
    $key_7b25 = { 2f 4d [2] 5b 55 [2] 1c 57 [2] 5b 46 [2] 15 4a [2] 19 40 [2] 0e 4b [2] 15 05 [2] 28 }

  condition:
    any of them
}