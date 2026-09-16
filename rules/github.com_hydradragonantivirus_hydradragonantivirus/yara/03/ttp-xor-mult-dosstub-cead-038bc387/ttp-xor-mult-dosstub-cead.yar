rule TTP_XOR_MULT_DOSStub_cead {
  strings:
    $key_cead = { 9a c5 [2] ee dd [2] a9 df [2] ee ce [2] a0 c2 [2] ac c8 [2] bb c3 [2] a0 8d [2] 9d }

  condition:
    any of them
}