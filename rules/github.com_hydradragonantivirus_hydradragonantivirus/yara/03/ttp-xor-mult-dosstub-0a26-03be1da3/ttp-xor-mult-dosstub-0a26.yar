rule TTP_XOR_MULT_DOSStub_0a26 {
  strings:
    $key_0a26 = { 5e 4e [2] 2a 56 [2] 6d 54 [2] 2a 45 [2] 64 49 [2] 68 43 [2] 7f 48 [2] 64 06 [2] 59 }

  condition:
    any of them
}