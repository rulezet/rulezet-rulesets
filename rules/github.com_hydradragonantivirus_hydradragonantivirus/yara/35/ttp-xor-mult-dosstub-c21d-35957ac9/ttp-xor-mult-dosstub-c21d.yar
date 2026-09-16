rule TTP_XOR_MULT_DOSStub_c21d {
  strings:
    $key_c21d = { 96 75 [2] e2 6d [2] a5 6f [2] e2 7e [2] ac 72 [2] a0 78 [2] b7 73 [2] ac 3d [2] 91 }

  condition:
    any of them
}