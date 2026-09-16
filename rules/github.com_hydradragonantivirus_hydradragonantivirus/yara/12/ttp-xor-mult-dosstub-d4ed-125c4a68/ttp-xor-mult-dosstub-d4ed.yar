rule TTP_XOR_MULT_DOSStub_d4ed {
  strings:
    $key_d4ed = { 80 85 [2] f4 9d [2] b3 9f [2] f4 8e [2] ba 82 [2] b6 88 [2] a1 83 [2] ba cd [2] 87 }

  condition:
    any of them
}