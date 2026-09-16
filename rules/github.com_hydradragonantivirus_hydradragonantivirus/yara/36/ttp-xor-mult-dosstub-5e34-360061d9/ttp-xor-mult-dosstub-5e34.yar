rule TTP_XOR_MULT_DOSStub_5e34 {
  strings:
    $key_5e34 = { 0a 5c [2] 7e 44 [2] 39 46 [2] 7e 57 [2] 30 5b [2] 3c 51 [2] 2b 5a [2] 30 14 [2] 0d }

  condition:
    any of them
}