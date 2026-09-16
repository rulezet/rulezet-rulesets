rule TTP_XOR_MULT_DOSStub_7e7f {
  strings:
    $key_7e7f = { 2a 17 [2] 5e 0f [2] 19 0d [2] 5e 1c [2] 10 10 [2] 1c 1a [2] 0b 11 [2] 10 5f [2] 2d }

  condition:
    any of them
}