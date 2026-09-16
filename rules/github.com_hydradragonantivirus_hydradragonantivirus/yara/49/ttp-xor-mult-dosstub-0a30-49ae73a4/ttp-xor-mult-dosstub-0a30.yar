rule TTP_XOR_MULT_DOSStub_0a30 {
  strings:
    $key_0a30 = { 5e 58 [2] 2a 40 [2] 6d 42 [2] 2a 53 [2] 64 5f [2] 68 55 [2] 7f 5e [2] 64 10 [2] 59 }

  condition:
    any of them
}