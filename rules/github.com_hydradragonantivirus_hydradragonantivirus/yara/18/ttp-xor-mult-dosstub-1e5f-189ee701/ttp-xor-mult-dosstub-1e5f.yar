rule TTP_XOR_MULT_DOSStub_1e5f {
  strings:
    $key_1e5f = { 4a 37 [2] 3e 2f [2] 79 2d [2] 3e 3c [2] 70 30 [2] 7c 3a [2] 6b 31 [2] 70 7f [2] 4d }

  condition:
    any of them
}