rule TTP_XOR_MULT_DOSStub_0b32 {
  strings:
    $key_0b32 = { 5f 5a [2] 2b 42 [2] 6c 40 [2] 2b 51 [2] 65 5d [2] 69 57 [2] 7e 5c [2] 65 12 [2] 58 }

  condition:
    any of them
}