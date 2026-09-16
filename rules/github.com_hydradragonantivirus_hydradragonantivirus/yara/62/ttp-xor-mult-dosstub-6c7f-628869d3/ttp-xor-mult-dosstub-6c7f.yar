rule TTP_XOR_MULT_DOSStub_6c7f {
  strings:
    $key_6c7f = { 38 17 [2] 4c 0f [2] 0b 0d [2] 4c 1c [2] 02 10 [2] 0e 1a [2] 19 11 [2] 02 5f [2] 3f }

  condition:
    any of them
}