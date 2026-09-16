rule TTP_XOR_MULT_DOSStub_3e44 {
  strings:
    $key_3e44 = { 6a 2c [2] 1e 34 [2] 59 36 [2] 1e 27 [2] 50 2b [2] 5c 21 [2] 4b 2a [2] 50 64 [2] 6d }

  condition:
    any of them
}