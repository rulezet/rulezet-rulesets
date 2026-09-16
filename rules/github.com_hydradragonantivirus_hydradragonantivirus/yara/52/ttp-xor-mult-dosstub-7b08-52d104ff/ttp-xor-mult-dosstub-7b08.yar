rule TTP_XOR_MULT_DOSStub_7b08 {
  strings:
    $key_7b08 = { 2f 60 [2] 5b 78 [2] 1c 7a [2] 5b 6b [2] 15 67 [2] 19 6d [2] 0e 66 [2] 15 28 [2] 28 }

  condition:
    any of them
}