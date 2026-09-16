rule TTP_XOR_MULT_DOSStub_0a31 {
  strings:
    $key_0a31 = { 5e 59 [2] 2a 41 [2] 6d 43 [2] 2a 52 [2] 64 5e [2] 68 54 [2] 7f 5f [2] 64 11 [2] 59 }

  condition:
    any of them
}