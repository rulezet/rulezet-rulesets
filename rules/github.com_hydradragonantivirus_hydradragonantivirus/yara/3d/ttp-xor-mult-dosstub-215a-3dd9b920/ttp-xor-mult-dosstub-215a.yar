rule TTP_XOR_MULT_DOSStub_215a {
  strings:
    $key_215a = { 75 32 [2] 01 2a [2] 46 28 [2] 01 39 [2] 4f 35 [2] 43 3f [2] 54 34 [2] 4f 7a [2] 72 }

  condition:
    any of them
}