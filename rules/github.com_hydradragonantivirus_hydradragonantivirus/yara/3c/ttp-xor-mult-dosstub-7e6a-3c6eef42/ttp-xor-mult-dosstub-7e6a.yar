rule TTP_XOR_MULT_DOSStub_7e6a {
  strings:
    $key_7e6a = { 2a 02 [2] 5e 1a [2] 19 18 [2] 5e 09 [2] 10 05 [2] 1c 0f [2] 0b 04 [2] 10 4a [2] 2d }

  condition:
    any of them
}