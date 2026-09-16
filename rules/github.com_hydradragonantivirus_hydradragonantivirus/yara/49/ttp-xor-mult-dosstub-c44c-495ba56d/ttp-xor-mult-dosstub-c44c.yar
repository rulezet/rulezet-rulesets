rule TTP_XOR_MULT_DOSStub_c44c {
  strings:
    $key_c44c = { 90 24 [2] e4 3c [2] a3 3e [2] e4 2f [2] aa 23 [2] a6 29 [2] b1 22 [2] aa 6c [2] 97 }

  condition:
    any of them
}