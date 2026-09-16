rule TTP_XOR_MULT_DOSStub_d75d {
  strings:
    $key_d75d = { 83 35 [2] f7 2d [2] b0 2f [2] f7 3e [2] b9 32 [2] b5 38 [2] a2 33 [2] b9 7d [2] 84 }

  condition:
    any of them
}