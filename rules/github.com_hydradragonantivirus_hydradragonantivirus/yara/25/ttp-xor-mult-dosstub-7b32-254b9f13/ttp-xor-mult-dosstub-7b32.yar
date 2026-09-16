rule TTP_XOR_MULT_DOSStub_7b32 {
  strings:
    $key_7b32 = { 2f 5a [2] 5b 42 [2] 1c 40 [2] 5b 51 [2] 15 5d [2] 19 57 [2] 0e 5c [2] 15 12 [2] 28 }

  condition:
    any of them
}