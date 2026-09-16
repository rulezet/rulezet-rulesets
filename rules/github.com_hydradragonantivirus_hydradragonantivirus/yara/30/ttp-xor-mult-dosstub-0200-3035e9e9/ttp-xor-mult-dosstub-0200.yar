rule TTP_XOR_MULT_DOSStub_0200 {
  strings:
    $key_0200 = { 56 68 [2] 22 70 [2] 65 72 [2] 22 63 [2] 6c 6f [2] 60 65 [2] 77 6e [2] 6c 20 [2] 51 }

  condition:
    any of them
}