rule TTP_XOR_MULT_DOSStub_1e3f {
  strings:
    $key_1e3f = { 4a 57 [2] 3e 4f [2] 79 4d [2] 3e 5c [2] 70 50 [2] 7c 5a [2] 6b 51 [2] 70 1f [2] 4d }

  condition:
    any of them
}