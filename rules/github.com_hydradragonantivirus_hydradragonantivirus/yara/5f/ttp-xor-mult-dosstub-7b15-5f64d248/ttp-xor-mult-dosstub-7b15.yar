rule TTP_XOR_MULT_DOSStub_7b15 {
  strings:
    $key_7b15 = { 2f 7d [2] 5b 65 [2] 1c 67 [2] 5b 76 [2] 15 7a [2] 19 70 [2] 0e 7b [2] 15 35 [2] 28 }

  condition:
    any of them
}