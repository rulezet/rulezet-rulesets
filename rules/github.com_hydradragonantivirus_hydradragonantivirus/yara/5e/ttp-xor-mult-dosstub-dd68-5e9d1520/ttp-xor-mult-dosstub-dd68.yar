rule TTP_XOR_MULT_DOSStub_dd68 {
  strings:
    $key_dd68 = { 89 00 [2] fd 18 [2] ba 1a [2] fd 0b [2] b3 07 [2] bf 0d [2] a8 06 [2] b3 48 [2] 8e }

  condition:
    any of them
}