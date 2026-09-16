rule TTP_XOR_MULT_DOSStub_0e3f {
  strings:
    $key_0e3f = { 5a 57 [2] 2e 4f [2] 69 4d [2] 2e 5c [2] 60 50 [2] 6c 5a [2] 7b 51 [2] 60 1f [2] 5d }

  condition:
    any of them
}