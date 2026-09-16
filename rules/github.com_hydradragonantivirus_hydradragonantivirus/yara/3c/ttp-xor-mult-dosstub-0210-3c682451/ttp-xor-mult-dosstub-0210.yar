rule TTP_XOR_MULT_DOSStub_0210 {
  strings:
    $key_0210 = { 56 78 [2] 22 60 [2] 65 62 [2] 22 73 [2] 6c 7f [2] 60 75 [2] 77 7e [2] 6c 30 [2] 51 }

  condition:
    any of them
}