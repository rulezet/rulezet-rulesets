rule TTP_XOR_MULT_DOSStub_c47d {
  strings:
    $key_c47d = { 90 15 [2] e4 0d [2] a3 0f [2] e4 1e [2] aa 12 [2] a6 18 [2] b1 13 [2] aa 5d [2] 97 }

  condition:
    any of them
}