rule TTP_XOR_MULT_DOSStub_0216 {
  strings:
    $key_0216 = { 56 7e [2] 22 66 [2] 65 64 [2] 22 75 [2] 6c 79 [2] 60 73 [2] 77 78 [2] 6c 36 [2] 51 }

  condition:
    any of them
}