rule TTP_XOR_MULT_DOSStub_e31d {
  strings:
    $key_e31d = { b7 75 [2] c3 6d [2] 84 6f [2] c3 7e [2] 8d 72 [2] 81 78 [2] 96 73 [2] 8d 3d [2] b0 }

  condition:
    any of them
}