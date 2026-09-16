rule TTP_XOR_MULT_DOSStub_0b3f {
  strings:
    $key_0b3f = { 5f 57 [2] 2b 4f [2] 6c 4d [2] 2b 5c [2] 65 50 [2] 69 5a [2] 7e 51 [2] 65 1f [2] 58 }

  condition:
    any of them
}