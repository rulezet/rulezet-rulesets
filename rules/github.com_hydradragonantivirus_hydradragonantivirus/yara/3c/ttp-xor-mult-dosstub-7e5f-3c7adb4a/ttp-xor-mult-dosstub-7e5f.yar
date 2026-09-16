rule TTP_XOR_MULT_DOSStub_7e5f {
  strings:
    $key_7e5f = { 2a 37 [2] 5e 2f [2] 19 2d [2] 5e 3c [2] 10 30 [2] 1c 3a [2] 0b 31 [2] 10 7f [2] 2d }

  condition:
    any of them
}