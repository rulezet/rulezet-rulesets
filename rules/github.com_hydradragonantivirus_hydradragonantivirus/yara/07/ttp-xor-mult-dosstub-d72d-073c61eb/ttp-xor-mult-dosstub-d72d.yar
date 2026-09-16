rule TTP_XOR_MULT_DOSStub_d72d {
  strings:
    $key_d72d = { 83 45 [2] f7 5d [2] b0 5f [2] f7 4e [2] b9 42 [2] b5 48 [2] a2 43 [2] b9 0d [2] 84 }

  condition:
    any of them
}