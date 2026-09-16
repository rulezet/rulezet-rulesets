rule TTP_XOR_MULT_DOSStub_0b6a {
  strings:
    $key_0b6a = { 5f 02 [2] 2b 1a [2] 6c 18 [2] 2b 09 [2] 65 05 [2] 69 0f [2] 7e 04 [2] 65 4a [2] 58 }

  condition:
    any of them
}