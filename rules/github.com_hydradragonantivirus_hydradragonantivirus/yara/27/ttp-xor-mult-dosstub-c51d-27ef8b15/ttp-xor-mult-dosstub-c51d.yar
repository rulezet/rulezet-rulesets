rule TTP_XOR_MULT_DOSStub_c51d {
  strings:
    $key_c51d = { 91 75 [2] e5 6d [2] a2 6f [2] e5 7e [2] ab 72 [2] a7 78 [2] b0 73 [2] ab 3d [2] 96 }

  condition:
    any of them
}