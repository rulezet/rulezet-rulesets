rule TTP_XOR_MULT_DOSStub_057f {
  strings:
    $key_057f = { 51 17 [2] 25 0f [2] 62 0d [2] 25 1c [2] 6b 10 [2] 67 1a [2] 70 11 [2] 6b 5f [2] 56 }

  condition:
    any of them
}