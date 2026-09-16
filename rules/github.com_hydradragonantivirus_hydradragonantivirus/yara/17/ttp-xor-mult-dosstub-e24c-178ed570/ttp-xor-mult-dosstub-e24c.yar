rule TTP_XOR_MULT_DOSStub_e24c {
  strings:
    $key_e24c = { b6 24 [2] c2 3c [2] 85 3e [2] c2 2f [2] 8c 23 [2] 80 29 [2] 97 22 [2] 8c 6c [2] b1 }

  condition:
    any of them
}