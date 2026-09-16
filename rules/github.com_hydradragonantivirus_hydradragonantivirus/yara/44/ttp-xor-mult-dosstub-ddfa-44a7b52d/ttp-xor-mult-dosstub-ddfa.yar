rule TTP_XOR_MULT_DOSStub_ddfa {
  strings:
    $key_ddfa = { 89 92 [2] fd 8a [2] ba 88 [2] fd 99 [2] b3 95 [2] bf 9f [2] a8 94 [2] b3 da [2] 8e }

  condition:
    any of them
}