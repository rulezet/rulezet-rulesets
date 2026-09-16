rule TTP_XOR_MULT_DOSStub_495f {
  strings:
    $key_495f = { 1d 37 [2] 69 2f [2] 2e 2d [2] 69 3c [2] 27 30 [2] 2b 3a [2] 3c 31 [2] 27 7f [2] 1a }

  condition:
    any of them
}