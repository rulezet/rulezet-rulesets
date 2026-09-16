rule TTP_XOR_MULT_DOSStub_f007 {
  strings:
    $key_f007 = { a4 6f [2] d0 77 [2] 97 75 [2] d0 64 [2] 9e 68 [2] 92 62 [2] 85 69 [2] 9e 27 [2] a3 }

  condition:
    any of them
}