rule TTP_XOR_MULT_DOSStub_0a76 {
  strings:
    $key_0a76 = { 5e 1e [2] 2a 06 [2] 6d 04 [2] 2a 15 [2] 64 19 [2] 68 13 [2] 7f 18 [2] 64 56 [2] 59 }

  condition:
    any of them
}