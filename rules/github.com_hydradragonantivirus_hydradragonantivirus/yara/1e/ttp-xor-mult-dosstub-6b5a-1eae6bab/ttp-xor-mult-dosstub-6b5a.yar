rule TTP_XOR_MULT_DOSStub_6b5a {
  strings:
    $key_6b5a = { 3f 32 [2] 4b 2a [2] 0c 28 [2] 4b 39 [2] 05 35 [2] 09 3f [2] 1e 34 [2] 05 7a [2] 38 }

  condition:
    any of them
}