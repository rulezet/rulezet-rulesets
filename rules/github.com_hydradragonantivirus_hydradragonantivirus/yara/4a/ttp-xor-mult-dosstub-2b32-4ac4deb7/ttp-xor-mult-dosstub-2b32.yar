rule TTP_XOR_MULT_DOSStub_2b32 {
  strings:
    $key_2b32 = { 7f 5a [2] 0b 42 [2] 4c 40 [2] 0b 51 [2] 45 5d [2] 49 57 [2] 5e 5c [2] 45 12 [2] 78 }

  condition:
    any of them
}