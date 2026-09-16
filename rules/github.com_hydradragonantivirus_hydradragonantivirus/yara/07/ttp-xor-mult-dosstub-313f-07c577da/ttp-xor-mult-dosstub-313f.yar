rule TTP_XOR_MULT_DOSStub_313f {
  strings:
    $key_313f = { 65 57 [2] 11 4f [2] 56 4d [2] 11 5c [2] 5f 50 [2] 53 5a [2] 44 51 [2] 5f 1f [2] 62 }

  condition:
    any of them
}