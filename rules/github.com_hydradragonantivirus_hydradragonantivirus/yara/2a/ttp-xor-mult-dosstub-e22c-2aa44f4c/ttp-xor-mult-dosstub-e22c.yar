rule TTP_XOR_MULT_DOSStub_e22c {
  strings:
    $key_e22c = { b6 44 [2] c2 5c [2] 85 5e [2] c2 4f [2] 8c 43 [2] 80 49 [2] 97 42 [2] 8c 0c [2] b1 }

  condition:
    any of them
}