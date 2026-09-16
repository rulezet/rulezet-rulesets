rule TTP_XOR_MULT_DOSStub_157f {
  strings:
    $key_157f = { 41 17 [2] 35 0f [2] 72 0d [2] 35 1c [2] 7b 10 [2] 77 1a [2] 60 11 [2] 7b 5f [2] 46 }

  condition:
    any of them
}