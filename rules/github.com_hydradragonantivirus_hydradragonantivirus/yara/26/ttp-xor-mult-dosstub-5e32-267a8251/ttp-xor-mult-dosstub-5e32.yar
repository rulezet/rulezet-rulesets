rule TTP_XOR_MULT_DOSStub_5e32 {
  strings:
    $key_5e32 = { 0a 5a [2] 7e 42 [2] 39 40 [2] 7e 51 [2] 30 5d [2] 3c 57 [2] 2b 5c [2] 30 12 [2] 0d }

  condition:
    any of them
}