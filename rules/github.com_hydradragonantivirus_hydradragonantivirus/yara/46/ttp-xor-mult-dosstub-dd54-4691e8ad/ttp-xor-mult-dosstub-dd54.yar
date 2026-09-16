rule TTP_XOR_MULT_DOSStub_dd54 {
  strings:
    $key_dd54 = { 89 3c [2] fd 24 [2] ba 26 [2] fd 37 [2] b3 3b [2] bf 31 [2] a8 3a [2] b3 74 [2] 8e }

  condition:
    any of them
}