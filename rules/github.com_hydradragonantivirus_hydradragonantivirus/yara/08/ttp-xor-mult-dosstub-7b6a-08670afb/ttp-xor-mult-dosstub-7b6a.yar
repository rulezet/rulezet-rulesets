rule TTP_XOR_MULT_DOSStub_7b6a {
  strings:
    $key_7b6a = { 2f 02 [2] 5b 1a [2] 1c 18 [2] 5b 09 [2] 15 05 [2] 19 0f [2] 0e 04 [2] 15 4a [2] 28 }

  condition:
    any of them
}