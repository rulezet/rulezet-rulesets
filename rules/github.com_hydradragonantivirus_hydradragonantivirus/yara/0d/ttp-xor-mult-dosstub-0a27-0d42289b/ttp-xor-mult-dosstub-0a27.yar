rule TTP_XOR_MULT_DOSStub_0a27 {
  strings:
    $key_0a27 = { 5e 4f [2] 2a 57 [2] 6d 55 [2] 2a 44 [2] 64 48 [2] 68 42 [2] 7f 49 [2] 64 07 [2] 59 }

  condition:
    any of them
}