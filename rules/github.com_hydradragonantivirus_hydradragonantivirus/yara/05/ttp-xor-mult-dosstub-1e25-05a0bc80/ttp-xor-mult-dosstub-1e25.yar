rule TTP_XOR_MULT_DOSStub_1e25 {
  strings:
    $key_1e25 = { 4a 4d [2] 3e 55 [2] 79 57 [2] 3e 46 [2] 70 4a [2] 7c 40 [2] 6b 4b [2] 70 05 [2] 4d }

  condition:
    any of them
}