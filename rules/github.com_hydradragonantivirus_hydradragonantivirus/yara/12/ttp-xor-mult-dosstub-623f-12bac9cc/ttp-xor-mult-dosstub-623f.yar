rule TTP_XOR_MULT_DOSStub_623f {
  strings:
    $key_623f = { 36 57 [2] 42 4f [2] 05 4d [2] 42 5c [2] 0c 50 [2] 00 5a [2] 17 51 [2] 0c 1f [2] 31 }

  condition:
    any of them
}