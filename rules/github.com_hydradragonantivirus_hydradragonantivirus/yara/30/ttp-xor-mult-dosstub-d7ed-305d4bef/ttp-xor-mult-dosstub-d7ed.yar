rule TTP_XOR_MULT_DOSStub_d7ed {
  strings:
    $key_d7ed = { 83 85 [2] f7 9d [2] b0 9f [2] f7 8e [2] b9 82 [2] b5 88 [2] a2 83 [2] b9 cd [2] 84 }

  condition:
    any of them
}