rule TTP_XOR_MULT_DOSStub_d72c {
  strings:
    $key_d72c = { 83 44 [2] f7 5c [2] b0 5e [2] f7 4f [2] b9 43 [2] b5 49 [2] a2 42 [2] b9 0c [2] 84 }

  condition:
    any of them
}