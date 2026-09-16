rule TTP_XOR_MULT_DOSStub_d76d {
  strings:
    $key_d76d = { 83 05 [2] f7 1d [2] b0 1f [2] f7 0e [2] b9 02 [2] b5 08 [2] a2 03 [2] b9 4d [2] 84 }

  condition:
    any of them
}