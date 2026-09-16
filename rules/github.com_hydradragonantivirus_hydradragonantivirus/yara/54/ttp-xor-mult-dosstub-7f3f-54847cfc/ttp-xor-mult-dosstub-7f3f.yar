rule TTP_XOR_MULT_DOSStub_7f3f {
  strings:
    $key_7f3f = { 2b 57 [2] 5f 4f [2] 18 4d [2] 5f 5c [2] 11 50 [2] 1d 5a [2] 0a 51 [2] 11 1f [2] 2c }

  condition:
    any of them
}