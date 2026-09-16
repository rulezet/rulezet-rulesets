rule TTP_XOR_MULT_DOSStub_e22d {
  strings:
    $key_e22d = { b6 45 [2] c2 5d [2] 85 5f [2] c2 4e [2] 8c 42 [2] 80 48 [2] 97 43 [2] 8c 0d [2] b1 }

  condition:
    any of them
}