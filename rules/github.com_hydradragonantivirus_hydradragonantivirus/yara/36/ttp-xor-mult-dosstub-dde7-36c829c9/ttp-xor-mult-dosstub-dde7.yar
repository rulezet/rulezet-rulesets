rule TTP_XOR_MULT_DOSStub_dde7 {
  strings:
    $key_dde7 = { 89 8f [2] fd 97 [2] ba 95 [2] fd 84 [2] b3 88 [2] bf 82 [2] a8 89 [2] b3 c7 [2] 8e }

  condition:
    any of them
}