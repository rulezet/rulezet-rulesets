rule TTP_XOR_MULT_DOSStub_ddef {
  strings:
    $key_ddef = { 89 87 [2] fd 9f [2] ba 9d [2] fd 8c [2] b3 80 [2] bf 8a [2] a8 81 [2] b3 cf [2] 8e }

  condition:
    any of them
}