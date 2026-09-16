rule TTP_XOR_MULT_DOSStub_257f {
  strings:
    $key_257f = { 71 17 [2] 05 0f [2] 42 0d [2] 05 1c [2] 4b 10 [2] 47 1a [2] 50 11 [2] 4b 5f [2] 76 }

  condition:
    any of them
}