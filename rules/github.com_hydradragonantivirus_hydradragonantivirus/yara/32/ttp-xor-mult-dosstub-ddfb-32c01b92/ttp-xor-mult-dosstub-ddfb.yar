rule TTP_XOR_MULT_DOSStub_ddfb {
  strings:
    $key_ddfb = { 89 93 [2] fd 8b [2] ba 89 [2] fd 98 [2] b3 94 [2] bf 9e [2] a8 95 [2] b3 db [2] 8e }

  condition:
    any of them
}