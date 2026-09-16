rule TTP_XOR_MULT_DOSStub_3e72 {
  strings:
    $key_3e72 = { 6a 1a [2] 1e 02 [2] 59 00 [2] 1e 11 [2] 50 1d [2] 5c 17 [2] 4b 1c [2] 50 52 [2] 6d }

  condition:
    any of them
}