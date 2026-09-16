rule TTP_XOR_MULT_DOSStub_ddfc {
  strings:
    $key_ddfc = { 89 94 [2] fd 8c [2] ba 8e [2] fd 9f [2] b3 93 [2] bf 99 [2] a8 92 [2] b3 dc [2] 8e }

  condition:
    any of them
}