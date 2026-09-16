rule TTP_XOR_MULT_DOSStub_5e5f {
  strings:
    $key_5e5f = { 0a 37 [2] 7e 2f [2] 39 2d [2] 7e 3c [2] 30 30 [2] 3c 3a [2] 2b 31 [2] 30 7f [2] 0d }

  condition:
    any of them
}