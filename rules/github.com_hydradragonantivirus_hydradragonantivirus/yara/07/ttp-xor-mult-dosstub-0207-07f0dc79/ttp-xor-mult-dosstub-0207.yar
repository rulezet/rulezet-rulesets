rule TTP_XOR_MULT_DOSStub_0207 {
  strings:
    $key_0207 = { 56 6f [2] 22 77 [2] 65 75 [2] 22 64 [2] 6c 68 [2] 60 62 [2] 77 69 [2] 6c 27 [2] 51 }

  condition:
    any of them
}