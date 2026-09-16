rule TTP_XOR_MULT_DOSStub_dd69 {
  strings:
    $key_dd69 = { 89 01 [2] fd 19 [2] ba 1b [2] fd 0a [2] b3 06 [2] bf 0c [2] a8 07 [2] b3 49 [2] 8e }

  condition:
    any of them
}