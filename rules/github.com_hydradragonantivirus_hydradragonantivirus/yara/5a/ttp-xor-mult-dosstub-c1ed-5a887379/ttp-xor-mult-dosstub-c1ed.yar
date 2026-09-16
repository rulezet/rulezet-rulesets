rule TTP_XOR_MULT_DOSStub_c1ed {
  strings:
    $key_c1ed = { 95 85 [2] e1 9d [2] a6 9f [2] e1 8e [2] af 82 [2] a3 88 [2] b4 83 [2] af cd [2] 92 }

  condition:
    any of them
}