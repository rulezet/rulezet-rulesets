rule TTP_XOR_MULT_DOSStub_c424 {
  strings:
    $key_c424 = { 90 4c [2] e4 54 [2] a3 56 [2] e4 47 [2] aa 4b [2] a6 41 [2] b1 4a [2] aa 04 [2] 97 }

  condition:
    any of them
}