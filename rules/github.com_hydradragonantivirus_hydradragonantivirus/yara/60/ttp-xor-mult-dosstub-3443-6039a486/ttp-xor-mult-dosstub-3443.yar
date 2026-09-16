rule TTP_XOR_MULT_DOSStub_3443 {
  strings:
    $key_3443 = { 60 2b [2] 14 33 [2] 53 31 [2] 14 20 [2] 5a 2c [2] 56 26 [2] 41 2d [2] 5a 63 [2] 67 }

  condition:
    any of them
}