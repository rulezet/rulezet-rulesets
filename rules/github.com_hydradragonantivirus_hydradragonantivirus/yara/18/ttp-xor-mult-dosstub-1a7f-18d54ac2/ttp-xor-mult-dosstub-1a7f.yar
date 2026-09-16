rule TTP_XOR_MULT_DOSStub_1a7f {
  strings:
    $key_1a7f = { 4e 17 [2] 3a 0f [2] 7d 0d [2] 3a 1c [2] 74 10 [2] 78 1a [2] 6f 11 [2] 74 5f [2] 49 }

  condition:
    any of them
}