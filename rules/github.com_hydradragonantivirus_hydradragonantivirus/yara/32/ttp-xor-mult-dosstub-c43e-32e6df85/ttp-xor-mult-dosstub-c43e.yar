rule TTP_XOR_MULT_DOSStub_c43e {
  strings:
    $key_c43e = { 90 56 [2] e4 4e [2] a3 4c [2] e4 5d [2] aa 51 [2] a6 5b [2] b1 50 [2] aa 1e [2] 97 }

  condition:
    any of them
}