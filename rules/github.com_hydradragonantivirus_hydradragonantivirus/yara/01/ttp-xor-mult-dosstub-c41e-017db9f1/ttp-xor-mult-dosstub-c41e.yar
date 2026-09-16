rule TTP_XOR_MULT_DOSStub_c41e {
  strings:
    $key_c41e = { 90 76 [2] e4 6e [2] a3 6c [2] e4 7d [2] aa 71 [2] a6 7b [2] b1 70 [2] aa 3e [2] 97 }

  condition:
    any of them
}