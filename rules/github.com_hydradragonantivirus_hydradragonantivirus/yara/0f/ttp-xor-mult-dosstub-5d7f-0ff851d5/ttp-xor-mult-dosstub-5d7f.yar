rule TTP_XOR_MULT_DOSStub_5d7f {
  strings:
    $key_5d7f = { 09 17 [2] 7d 0f [2] 3a 0d [2] 7d 1c [2] 33 10 [2] 3f 1a [2] 28 11 [2] 33 5f [2] 0e }

  condition:
    any of them
}