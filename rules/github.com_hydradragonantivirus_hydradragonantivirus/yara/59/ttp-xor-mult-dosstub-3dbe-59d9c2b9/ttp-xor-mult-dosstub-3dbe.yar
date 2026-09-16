rule TTP_XOR_MULT_DOSStub_3dbe {
  strings:
    $key_3dbe = { 69 d6 [2] 1d ce [2] 5a cc [2] 1d dd [2] 53 d1 [2] 5f db [2] 48 d0 [2] 53 9e [2] 6e }

  condition:
    any of them
}