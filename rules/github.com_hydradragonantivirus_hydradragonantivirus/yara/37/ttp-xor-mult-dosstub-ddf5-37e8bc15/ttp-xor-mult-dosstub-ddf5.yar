rule TTP_XOR_MULT_DOSStub_ddf5 {
  strings:
    $key_ddf5 = { 89 9d [2] fd 85 [2] ba 87 [2] fd 96 [2] b3 9a [2] bf 90 [2] a8 9b [2] b3 d5 [2] 8e }

  condition:
    any of them
}