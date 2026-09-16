rule TTP_XOR_MULT_DOSStub_c6ed {
  strings:
    $key_c6ed = { 92 85 [2] e6 9d [2] a1 9f [2] e6 8e [2] a8 82 [2] a4 88 [2] b3 83 [2] a8 cd [2] 95 }

  condition:
    any of them
}