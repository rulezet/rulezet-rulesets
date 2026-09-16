rule TTP_XOR_MULT_DOSStub_0250 {
  strings:
    $key_0250 = { 56 38 [2] 22 20 [2] 65 22 [2] 22 33 [2] 6c 3f [2] 60 35 [2] 77 3e [2] 6c 70 [2] 51 }

  condition:
    any of them
}