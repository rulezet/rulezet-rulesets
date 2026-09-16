rule TTP_XOR_MULT_DOSStub_c429 {
  strings:
    $key_c429 = { 90 41 [2] e4 59 [2] a3 5b [2] e4 4a [2] aa 46 [2] a6 4c [2] b1 47 [2] aa 09 [2] 97 }

  condition:
    any of them
}