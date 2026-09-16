rule TTP_XOR_MULT_DOSStub_c443 {
  strings:
    $key_c443 = { 90 2b [2] e4 33 [2] a3 31 [2] e4 20 [2] aa 2c [2] a6 26 [2] b1 2d [2] aa 63 [2] 97 }

  condition:
    any of them
}