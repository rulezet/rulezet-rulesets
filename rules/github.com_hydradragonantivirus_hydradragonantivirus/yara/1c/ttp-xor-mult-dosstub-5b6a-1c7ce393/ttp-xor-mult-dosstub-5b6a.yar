rule TTP_XOR_MULT_DOSStub_5b6a {
  strings:
    $key_5b6a = { 0f 02 [2] 7b 1a [2] 3c 18 [2] 7b 09 [2] 35 05 [2] 39 0f [2] 2e 04 [2] 35 4a [2] 08 }

  condition:
    any of them
}