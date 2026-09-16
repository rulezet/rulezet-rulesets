rule TTP_XOR_MULT_DOSStub_c41b {
  strings:
    $key_c41b = { 90 73 [2] e4 6b [2] a3 69 [2] e4 78 [2] aa 74 [2] a6 7e [2] b1 75 [2] aa 3b [2] 97 }

  condition:
    any of them
}