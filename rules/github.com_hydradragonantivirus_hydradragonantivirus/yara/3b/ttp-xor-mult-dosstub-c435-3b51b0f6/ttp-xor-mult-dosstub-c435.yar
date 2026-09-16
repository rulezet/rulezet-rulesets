rule TTP_XOR_MULT_DOSStub_c435 {
  strings:
    $key_c435 = { 90 5d [2] e4 45 [2] a3 47 [2] e4 56 [2] aa 5a [2] a6 50 [2] b1 5b [2] aa 15 [2] 97 }

  condition:
    any of them
}