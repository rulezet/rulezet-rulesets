rule TTP_XOR_MULT_DOSStub_0a00 {
  strings:
    $key_0a00 = { 5e 68 [2] 2a 70 [2] 6d 72 [2] 2a 63 [2] 64 6f [2] 68 65 [2] 7f 6e [2] 64 20 [2] 59 }

  condition:
    any of them
}