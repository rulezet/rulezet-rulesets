rule TTP_XOR_MULT_DOSStub_e41d {
  strings:
    $key_e41d = { b0 75 [2] c4 6d [2] 83 6f [2] c4 7e [2] 8a 72 [2] 86 78 [2] 91 73 [2] 8a 3d [2] b7 }

  condition:
    any of them
}