rule TTP_XOR_MULT_DOSStub_d66d {
  strings:
    $key_d66d = { 82 05 [2] f6 1d [2] b1 1f [2] f6 0e [2] b8 02 [2] b4 08 [2] a3 03 [2] b8 4d [2] 85 }

  condition:
    any of them
}