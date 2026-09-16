rule TTP_XOR_MULT_DOSStub_6b2a {
  strings:
    $key_6b2a = { 3f 42 [2] 4b 5a [2] 0c 58 [2] 4b 49 [2] 05 45 [2] 09 4f [2] 1e 44 [2] 05 0a [2] 38 }

  condition:
    any of them
}