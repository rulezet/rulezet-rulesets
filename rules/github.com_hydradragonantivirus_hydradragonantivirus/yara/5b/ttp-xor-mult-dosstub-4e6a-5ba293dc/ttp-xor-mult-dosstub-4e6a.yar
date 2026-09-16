rule TTP_XOR_MULT_DOSStub_4e6a {
  strings:
    $key_4e6a = { 1a 02 [2] 6e 1a [2] 29 18 [2] 6e 09 [2] 20 05 [2] 2c 0f [2] 3b 04 [2] 20 4a [2] 1d }

  condition:
    any of them
}