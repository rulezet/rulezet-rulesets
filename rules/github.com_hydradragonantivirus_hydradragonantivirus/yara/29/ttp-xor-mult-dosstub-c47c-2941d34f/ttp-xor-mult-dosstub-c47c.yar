rule TTP_XOR_MULT_DOSStub_c47c {
  strings:
    $key_c47c = { 90 14 [2] e4 0c [2] a3 0e [2] e4 1f [2] aa 13 [2] a6 19 [2] b1 12 [2] aa 5c [2] 97 }

  condition:
    any of them
}