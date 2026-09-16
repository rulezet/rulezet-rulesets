rule TTP_XOR_MULT_DOSStub_dd38 {
  strings:
    $key_dd38 = { 89 50 [2] fd 48 [2] ba 4a [2] fd 5b [2] b3 57 [2] bf 5d [2] a8 56 [2] b3 18 [2] 8e }

  condition:
    any of them
}