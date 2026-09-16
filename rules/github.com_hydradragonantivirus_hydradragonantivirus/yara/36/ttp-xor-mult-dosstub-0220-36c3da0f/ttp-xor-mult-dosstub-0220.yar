rule TTP_XOR_MULT_DOSStub_0220 {
  strings:
    $key_0220 = { 56 48 [2] 22 50 [2] 65 52 [2] 22 43 [2] 6c 4f [2] 60 45 [2] 77 4e [2] 6c 00 [2] 51 }

  condition:
    any of them
}