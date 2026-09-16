rule TTP_XOR_MULT_DOSStub_415a {
  strings:
    $key_415a = { 15 32 [2] 61 2a [2] 26 28 [2] 61 39 [2] 2f 35 [2] 23 3f [2] 34 34 [2] 2f 7a [2] 12 }

  condition:
    any of them
}