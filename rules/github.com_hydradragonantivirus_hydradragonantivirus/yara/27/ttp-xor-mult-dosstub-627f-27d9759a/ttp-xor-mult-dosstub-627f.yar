rule TTP_XOR_MULT_DOSStub_627f {
  strings:
    $key_627f = { 36 17 [2] 42 0f [2] 05 0d [2] 42 1c [2] 0c 10 [2] 00 1a [2] 17 11 [2] 0c 5f [2] 31 }

  condition:
    any of them
}