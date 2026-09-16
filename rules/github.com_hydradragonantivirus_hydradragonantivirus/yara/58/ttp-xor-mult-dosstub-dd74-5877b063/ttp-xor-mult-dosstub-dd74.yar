rule TTP_XOR_MULT_DOSStub_dd74 {
  strings:
    $key_dd74 = { 89 1c [2] fd 04 [2] ba 06 [2] fd 17 [2] b3 1b [2] bf 11 [2] a8 1a [2] b3 54 [2] 8e }

  condition:
    any of them
}