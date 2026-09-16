rule TTP_XOR_MULT_DOSStub_0b33 {
  strings:
    $key_0b33 = { 5f 5b [2] 2b 43 [2] 6c 41 [2] 2b 50 [2] 65 5c [2] 69 56 [2] 7e 5d [2] 65 13 [2] 58 }

  condition:
    any of them
}