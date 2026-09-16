rule TTP_XOR_MULT_DOSStub_7e5a {
  strings:
    $key_7e5a = { 2a 32 [2] 5e 2a [2] 19 28 [2] 5e 39 [2] 10 35 [2] 1c 3f [2] 0b 34 [2] 10 7a [2] 2d }

  condition:
    any of them
}