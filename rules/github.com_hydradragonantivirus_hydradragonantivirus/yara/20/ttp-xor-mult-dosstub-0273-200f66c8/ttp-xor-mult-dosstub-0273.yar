rule TTP_XOR_MULT_DOSStub_0273 {
  strings:
    $key_0273 = { 56 1b [2] 22 03 [2] 65 01 [2] 22 10 [2] 6c 1c [2] 60 16 [2] 77 1d [2] 6c 53 [2] 51 }

  condition:
    any of them
}