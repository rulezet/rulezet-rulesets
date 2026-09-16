rule TTP_XOR_MULT_DOSStub_dd51 {
  strings:
    $key_dd51 = { 89 39 [2] fd 21 [2] ba 23 [2] fd 32 [2] b3 3e [2] bf 34 [2] a8 3f [2] b3 71 [2] 8e }

  condition:
    any of them
}