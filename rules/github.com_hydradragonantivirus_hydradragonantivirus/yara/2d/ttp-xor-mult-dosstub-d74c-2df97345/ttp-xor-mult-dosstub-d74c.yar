rule TTP_XOR_MULT_DOSStub_d74c {
  strings:
    $key_d74c = { 83 24 [2] f7 3c [2] b0 3e [2] f7 2f [2] b9 23 [2] b5 29 [2] a2 22 [2] b9 6c [2] 84 }

  condition:
    any of them
}