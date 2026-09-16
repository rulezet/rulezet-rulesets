rule TTP_XOR_MULT_DOSStub_0201 {
  strings:
    $key_0201 = { 56 69 [2] 22 71 [2] 65 73 [2] 22 62 [2] 6c 6e [2] 60 64 [2] 77 6f [2] 6c 21 [2] 51 }

  condition:
    any of them
}