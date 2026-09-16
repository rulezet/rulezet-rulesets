rule TTP_XOR_MULT_DOSStub_0af6 {
  strings:
    $key_0af6 = { 5e 9e [2] 2a 86 [2] 6d 84 [2] 2a 95 [2] 64 99 [2] 68 93 [2] 7f 98 [2] 64 d6 [2] 59 }

  condition:
    any of them
}