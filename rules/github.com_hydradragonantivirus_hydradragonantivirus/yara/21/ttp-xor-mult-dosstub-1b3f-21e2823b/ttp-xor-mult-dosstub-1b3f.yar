rule TTP_XOR_MULT_DOSStub_1b3f {
  strings:
    $key_1b3f = { 4f 57 [2] 3b 4f [2] 7c 4d [2] 3b 5c [2] 75 50 [2] 79 5a [2] 6e 51 [2] 75 1f [2] 48 }

  condition:
    any of them
}