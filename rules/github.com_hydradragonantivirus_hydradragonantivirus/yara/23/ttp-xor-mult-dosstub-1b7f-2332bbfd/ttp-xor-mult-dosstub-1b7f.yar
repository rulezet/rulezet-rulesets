rule TTP_XOR_MULT_DOSStub_1b7f {
  strings:
    $key_1b7f = { 4f 17 [2] 3b 0f [2] 7c 0d [2] 3b 1c [2] 75 10 [2] 79 1a [2] 6e 11 [2] 75 5f [2] 48 }

  condition:
    any of them
}