rule TTP_XOR_MULT_DOSStub_c46e {
  strings:
    $key_c46e = { 90 06 [2] e4 1e [2] a3 1c [2] e4 0d [2] aa 01 [2] a6 0b [2] b1 00 [2] aa 4e [2] 97 }

  condition:
    any of them
}