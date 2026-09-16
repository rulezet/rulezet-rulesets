rule TTP_XOR_MULT_DOSStub_0a07 {
  strings:
    $key_0a07 = { 5e 6f [2] 2a 77 [2] 6d 75 [2] 2a 64 [2] 64 68 [2] 68 62 [2] 7f 69 [2] 64 27 [2] 59 }

  condition:
    any of them
}