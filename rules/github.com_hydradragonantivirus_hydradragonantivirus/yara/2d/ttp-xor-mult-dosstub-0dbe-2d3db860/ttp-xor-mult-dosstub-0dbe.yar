rule TTP_XOR_MULT_DOSStub_0dbe {
  strings:
    $key_0dbe = { 59 d6 [2] 2d ce [2] 6a cc [2] 2d dd [2] 63 d1 [2] 6f db [2] 78 d0 [2] 63 9e [2] 5e }

  condition:
    any of them
}