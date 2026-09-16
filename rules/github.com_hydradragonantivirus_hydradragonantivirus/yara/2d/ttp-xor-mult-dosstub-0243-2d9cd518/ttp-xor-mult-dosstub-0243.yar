rule TTP_XOR_MULT_DOSStub_0243 {
  strings:
    $key_0243 = { 56 2b [2] 22 33 [2] 65 31 [2] 22 20 [2] 6c 2c [2] 60 26 [2] 77 2d [2] 6c 63 [2] 51 }

  condition:
    any of them
}