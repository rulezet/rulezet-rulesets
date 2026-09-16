rule TTP_XOR_MULT_DOSStub_0af1 {
  strings:
    $key_0af1 = { 5e 99 [2] 2a 81 [2] 6d 83 [2] 2a 92 [2] 64 9e [2] 68 94 [2] 7f 9f [2] 64 d1 [2] 59 }

  condition:
    any of them
}