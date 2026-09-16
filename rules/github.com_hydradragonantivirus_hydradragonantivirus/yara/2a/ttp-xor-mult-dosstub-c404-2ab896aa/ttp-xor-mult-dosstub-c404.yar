rule TTP_XOR_MULT_DOSStub_c404 {
  strings:
    $key_c404 = { 90 6c [2] e4 74 [2] a3 76 [2] e4 67 [2] aa 6b [2] a6 61 [2] b1 6a [2] aa 24 [2] 97 }

  condition:
    any of them
}