rule TTP_XOR_MULT_DOSStub_c4fa {
  strings:
    $key_c4fa = { 90 92 [2] e4 8a [2] a3 88 [2] e4 99 [2] aa 95 [2] a6 9f [2] b1 94 [2] aa da [2] 97 }

  condition:
    any of them
}