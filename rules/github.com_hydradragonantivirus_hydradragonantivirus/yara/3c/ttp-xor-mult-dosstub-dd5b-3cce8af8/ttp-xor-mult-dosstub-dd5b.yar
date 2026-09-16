rule TTP_XOR_MULT_DOSStub_dd5b {
  strings:
    $key_dd5b = { 89 33 [2] fd 2b [2] ba 29 [2] fd 38 [2] b3 34 [2] bf 3e [2] a8 35 [2] b3 7b [2] 8e }

  condition:
    any of them
}