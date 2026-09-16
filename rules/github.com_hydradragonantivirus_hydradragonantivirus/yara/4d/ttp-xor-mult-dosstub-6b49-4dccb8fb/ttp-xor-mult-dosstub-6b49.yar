rule TTP_XOR_MULT_DOSStub_6b49 {
  strings:
    $key_6b49 = { 3f 21 [2] 4b 39 [2] 0c 3b [2] 4b 2a [2] 05 26 [2] 09 2c [2] 1e 27 [2] 05 69 [2] 38 }

  condition:
    any of them
}