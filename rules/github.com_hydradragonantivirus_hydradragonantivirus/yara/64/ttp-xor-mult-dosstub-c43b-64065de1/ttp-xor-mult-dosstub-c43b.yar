rule TTP_XOR_MULT_DOSStub_c43b {
  strings:
    $key_c43b = { 90 53 [2] e4 4b [2] a3 49 [2] e4 58 [2] aa 54 [2] a6 5e [2] b1 55 [2] aa 1b [2] 97 }

  condition:
    any of them
}