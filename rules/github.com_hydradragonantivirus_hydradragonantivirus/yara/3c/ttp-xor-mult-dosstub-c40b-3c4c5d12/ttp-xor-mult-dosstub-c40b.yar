rule TTP_XOR_MULT_DOSStub_c40b {
  strings:
    $key_c40b = { 90 63 [2] e4 7b [2] a3 79 [2] e4 68 [2] aa 64 [2] a6 6e [2] b1 65 [2] aa 2b [2] 97 }

  condition:
    any of them
}