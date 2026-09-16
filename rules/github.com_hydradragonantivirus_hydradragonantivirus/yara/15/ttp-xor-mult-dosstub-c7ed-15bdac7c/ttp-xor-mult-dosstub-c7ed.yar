rule TTP_XOR_MULT_DOSStub_c7ed {
  strings:
    $key_c7ed = { 93 85 [2] e7 9d [2] a0 9f [2] e7 8e [2] a9 82 [2] a5 88 [2] b2 83 [2] a9 cd [2] 94 }

  condition:
    any of them
}