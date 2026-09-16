rule TTP_XOR_MULT_DOSStub_c26d {
  strings:
    $key_c26d = { 96 05 [2] e2 1d [2] a5 1f [2] e2 0e [2] ac 02 [2] a0 08 [2] b7 03 [2] ac 4d [2] 91 }

  condition:
    any of them
}