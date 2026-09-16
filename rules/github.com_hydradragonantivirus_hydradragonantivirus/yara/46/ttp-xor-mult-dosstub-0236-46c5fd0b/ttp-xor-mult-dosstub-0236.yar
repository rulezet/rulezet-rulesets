rule TTP_XOR_MULT_DOSStub_0236 {
  strings:
    $key_0236 = { 56 5e [2] 22 46 [2] 65 44 [2] 22 55 [2] 6c 59 [2] 60 53 [2] 77 58 [2] 6c 16 [2] 51 }

  condition:
    any of them
}