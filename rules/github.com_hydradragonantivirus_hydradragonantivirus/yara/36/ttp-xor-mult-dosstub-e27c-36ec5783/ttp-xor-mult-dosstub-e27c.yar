rule TTP_XOR_MULT_DOSStub_e27c {
  strings:
    $key_e27c = { b6 14 [2] c2 0c [2] 85 0e [2] c2 1f [2] 8c 13 [2] 80 19 [2] 97 12 [2] 8c 5c [2] b1 }

  condition:
    any of them
}