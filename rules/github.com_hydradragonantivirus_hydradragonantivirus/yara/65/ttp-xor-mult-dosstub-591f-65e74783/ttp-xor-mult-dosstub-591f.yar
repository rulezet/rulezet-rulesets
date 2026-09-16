rule TTP_XOR_MULT_DOSStub_591f {
  strings:
    $key_591f = { 0d 77 [2] 79 6f [2] 3e 6d [2] 79 7c [2] 37 70 [2] 3b 7a [2] 2c 71 [2] 37 3f [2] 0a }

  condition:
    any of them
}