rule TTP_XOR_MULT_DOSStub_7e3a {
  strings:
    $key_7e3a = { 2a 52 [2] 5e 4a [2] 19 48 [2] 5e 59 [2] 10 55 [2] 1c 5f [2] 0b 54 [2] 10 1a [2] 2d }

  condition:
    any of them
}