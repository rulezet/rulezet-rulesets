rule TTP_XOR_MULT_DOSStub_dd09 {
  strings:
    $key_dd09 = { 89 61 [2] fd 79 [2] ba 7b [2] fd 6a [2] b3 66 [2] bf 6c [2] a8 67 [2] b3 29 [2] 8e }

  condition:
    any of them
}