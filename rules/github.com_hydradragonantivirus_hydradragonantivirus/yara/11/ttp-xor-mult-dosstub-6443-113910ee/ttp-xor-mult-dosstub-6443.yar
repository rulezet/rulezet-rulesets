rule TTP_XOR_MULT_DOSStub_6443 {
  strings:
    $key_6443 = { 30 2b [2] 44 33 [2] 03 31 [2] 44 20 [2] 0a 2c [2] 06 26 [2] 11 2d [2] 0a 63 [2] 37 }

  condition:
    any of them
}