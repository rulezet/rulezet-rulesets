rule TTP_XOR_MULT_DOSStub_ddf4 {
  strings:
    $key_ddf4 = { 89 9c [2] fd 84 [2] ba 86 [2] fd 97 [2] b3 9b [2] bf 91 [2] a8 9a [2] b3 d4 [2] 8e }

  condition:
    any of them
}