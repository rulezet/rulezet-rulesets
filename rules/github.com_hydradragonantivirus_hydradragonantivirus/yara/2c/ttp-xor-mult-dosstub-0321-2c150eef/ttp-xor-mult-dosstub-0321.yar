rule TTP_XOR_MULT_DOSStub_0321 {
  strings:
    $key_0321 = { 57 49 [2] 23 51 [2] 64 53 [2] 23 42 [2] 6d 4e [2] 61 44 [2] 76 4f [2] 6d 01 [2] 50 }

  condition:
    any of them
}