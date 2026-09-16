rule TTP_XOR_MULT_DOSStub_095f {
  strings:
    $key_095f = { 5d 37 [2] 29 2f [2] 6e 2d [2] 29 3c [2] 67 30 [2] 6b 3a [2] 7c 31 [2] 67 7f [2] 5a }

  condition:
    any of them
}