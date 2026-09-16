rule TTP_XOR_MULT_DOSStub_ddf9 {
  strings:
    $key_ddf9 = { 89 91 [2] fd 89 [2] ba 8b [2] fd 9a [2] b3 96 [2] bf 9c [2] a8 97 [2] b3 d9 [2] 8e }

  condition:
    any of them
}