rule TTP_XOR_MULT_DOSStub_1e7f {
  strings:
    $key_1e7f = { 4a 17 [2] 3e 0f [2] 79 0d [2] 3e 1c [2] 70 10 [2] 7c 1a [2] 6b 11 [2] 70 5f [2] 4d }

  condition:
    any of them
}