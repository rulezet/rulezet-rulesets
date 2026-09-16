rule TTP_XOR_MULT_DOSStub_037f {
  strings:
    $key_037f = { 57 17 [2] 23 0f [2] 64 0d [2] 23 1c [2] 6d 10 [2] 61 1a [2] 76 11 [2] 6d 5f [2] 50 }

  condition:
    any of them
}