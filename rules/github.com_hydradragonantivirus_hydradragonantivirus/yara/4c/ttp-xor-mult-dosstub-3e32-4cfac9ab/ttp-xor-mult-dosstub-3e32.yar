rule TTP_XOR_MULT_DOSStub_3e32 {
  strings:
    $key_3e32 = { 6a 5a [2] 1e 42 [2] 59 40 [2] 1e 51 [2] 50 5d [2] 5c 57 [2] 4b 5c [2] 50 12 [2] 6d }

  condition:
    any of them
}