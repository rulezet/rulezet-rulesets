rule TTP_XOR_MULT_DOSStub_dd61 {
  strings:
    $key_dd61 = { 89 09 [2] fd 11 [2] ba 13 [2] fd 02 [2] b3 0e [2] bf 04 [2] a8 0f [2] b3 41 [2] 8e }

  condition:
    any of them
}