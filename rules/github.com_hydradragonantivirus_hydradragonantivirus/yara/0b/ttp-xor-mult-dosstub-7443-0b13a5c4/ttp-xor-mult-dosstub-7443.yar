rule TTP_XOR_MULT_DOSStub_7443 {
  strings:
    $key_7443 = { 20 2b [2] 54 33 [2] 13 31 [2] 54 20 [2] 1a 2c [2] 16 26 [2] 01 2d [2] 1a 63 [2] 27 }

  condition:
    any of them
}