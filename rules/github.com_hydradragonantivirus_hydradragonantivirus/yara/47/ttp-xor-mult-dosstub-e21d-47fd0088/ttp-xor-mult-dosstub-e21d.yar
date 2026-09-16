rule TTP_XOR_MULT_DOSStub_e21d {
  strings:
    $key_e21d = { b6 75 [2] c2 6d [2] 85 6f [2] c2 7e [2] 8c 72 [2] 80 78 [2] 97 73 [2] 8c 3d [2] b1 }

  condition:
    any of them
}