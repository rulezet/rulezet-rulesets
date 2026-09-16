rule TTP_XOR_MULT_DOSStub_c413 {
  strings:
    $key_c413 = { 90 7b [2] e4 63 [2] a3 61 [2] e4 70 [2] aa 7c [2] a6 76 [2] b1 7d [2] aa 33 [2] 97 }

  condition:
    any of them
}