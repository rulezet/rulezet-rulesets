rule TTP_XOR_MULT_DOSStub_6c33 {
  strings:
    $key_6c33 = { 38 5b [2] 4c 43 [2] 0b 41 [2] 4c 50 [2] 02 5c [2] 0e 56 [2] 19 5d [2] 02 13 [2] 3f }

  condition:
    any of them
}