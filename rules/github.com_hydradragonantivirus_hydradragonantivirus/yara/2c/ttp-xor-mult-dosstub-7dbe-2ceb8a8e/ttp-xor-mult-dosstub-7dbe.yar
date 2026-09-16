rule TTP_XOR_MULT_DOSStub_7dbe {
  strings:
    $key_7dbe = { 29 d6 [2] 5d ce [2] 1a cc [2] 5d dd [2] 13 d1 [2] 1f db [2] 08 d0 [2] 13 9e [2] 2e }

  condition:
    any of them
}