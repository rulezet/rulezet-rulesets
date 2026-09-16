rule TTP_XOR_MULT_DOSStub_02e0 {
  strings:
    $key_02e0 = { 56 88 [2] 22 90 [2] 65 92 [2] 22 83 [2] 6c 8f [2] 60 85 [2] 77 8e [2] 6c c0 [2] 51 }

  condition:
    any of them
}