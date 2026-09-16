rule TTP_XOR_MULT_DOSStub_ddee {
  strings:
    $key_ddee = { 89 86 [2] fd 9e [2] ba 9c [2] fd 8d [2] b3 81 [2] bf 8b [2] a8 80 [2] b3 ce [2] 8e }

  condition:
    any of them
}