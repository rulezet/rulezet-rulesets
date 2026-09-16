rule TTP_XOR_MULT_DOSStub_6b4a {
  strings:
    $key_6b4a = { 3f 22 [2] 4b 3a [2] 0c 38 [2] 4b 29 [2] 05 25 [2] 09 2f [2] 1e 24 [2] 05 6a [2] 38 }

  condition:
    any of them
}