rule TTP_XOR_MULT_DOSStub_dd78 {
  strings:
    $key_dd78 = { 89 10 [2] fd 08 [2] ba 0a [2] fd 1b [2] b3 17 [2] bf 1d [2] a8 16 [2] b3 58 [2] 8e }

  condition:
    any of them
}