rule TTP_XOR_MULT_DOSStub_3e15 {
  strings:
    $key_3e15 = { 6a 7d [2] 1e 65 [2] 59 67 [2] 1e 76 [2] 50 7a [2] 5c 70 [2] 4b 7b [2] 50 35 [2] 6d }

  condition:
    any of them
}