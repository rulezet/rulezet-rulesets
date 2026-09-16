rule TTP_XOR_MULT_DOSStub_0a51 {
  strings:
    $key_0a51 = { 5e 39 [2] 2a 21 [2] 6d 23 [2] 2a 32 [2] 64 3e [2] 68 34 [2] 7f 3f [2] 64 71 [2] 59 }

  condition:
    any of them
}