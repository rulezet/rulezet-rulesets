rule TTP_XOR_MULT_DOSStub_4e39 {
  strings:
    $key_4e39 = { 1a 51 [2] 6e 49 [2] 29 4b [2] 6e 5a [2] 20 56 [2] 2c 5c [2] 3b 57 [2] 20 19 [2] 1d }

  condition:
    any of them
}