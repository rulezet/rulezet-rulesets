rule TTP_XOR_MULT_DOSStub_6d32 {
  strings:
    $key_6d32 = { 39 5a [2] 4d 42 [2] 0a 40 [2] 4d 51 [2] 03 5d [2] 0f 57 [2] 18 5c [2] 03 12 [2] 3e }

  condition:
    any of them
}