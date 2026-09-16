rule TTP_XOR_MULT_DOSStub_c41d {
  strings:
    $key_c41d = { 90 75 [2] e4 6d [2] a3 6f [2] e4 7e [2] aa 72 [2] a6 78 [2] b1 73 [2] aa 3d [2] 97 }

  condition:
    any of them
}