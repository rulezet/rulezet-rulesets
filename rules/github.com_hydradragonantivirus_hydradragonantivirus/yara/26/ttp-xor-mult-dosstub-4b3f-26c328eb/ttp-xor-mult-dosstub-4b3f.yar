rule TTP_XOR_MULT_DOSStub_4b3f {
  strings:
    $key_4b3f = { 1f 57 [2] 6b 4f [2] 2c 4d [2] 6b 5c [2] 25 50 [2] 29 5a [2] 3e 51 [2] 25 1f [2] 18 }

  condition:
    any of them
}