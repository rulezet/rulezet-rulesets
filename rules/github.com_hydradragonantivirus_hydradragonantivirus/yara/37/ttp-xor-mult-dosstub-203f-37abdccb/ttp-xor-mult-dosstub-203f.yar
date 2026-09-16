rule TTP_XOR_MULT_DOSStub_203f {
  strings:
    $key_203f = { 74 57 [2] 00 4f [2] 47 4d [2] 00 5c [2] 4e 50 [2] 42 5a [2] 55 51 [2] 4e 1f [2] 73 }

  condition:
    any of them
}