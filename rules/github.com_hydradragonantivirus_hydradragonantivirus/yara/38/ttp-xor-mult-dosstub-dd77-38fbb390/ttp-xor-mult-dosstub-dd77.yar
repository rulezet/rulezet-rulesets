rule TTP_XOR_MULT_DOSStub_dd77 {
  strings:
    $key_dd77 = { 89 1f [2] fd 07 [2] ba 05 [2] fd 14 [2] b3 18 [2] bf 12 [2] a8 19 [2] b3 57 [2] 8e }

  condition:
    any of them
}