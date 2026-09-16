rule TTP_XOR_MULT_DOSStub_1dbe {
  strings:
    $key_1dbe = { 49 d6 [2] 3d ce [2] 7a cc [2] 3d dd [2] 73 d1 [2] 7f db [2] 68 d0 [2] 73 9e [2] 4e }

  condition:
    any of them
}