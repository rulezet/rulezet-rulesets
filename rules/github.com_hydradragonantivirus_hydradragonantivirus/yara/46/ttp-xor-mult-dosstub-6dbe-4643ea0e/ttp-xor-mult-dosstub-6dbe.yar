rule TTP_XOR_MULT_DOSStub_6dbe {
  strings:
    $key_6dbe = { 39 d6 [2] 4d ce [2] 0a cc [2] 4d dd [2] 03 d1 [2] 0f db [2] 18 d0 [2] 03 9e [2] 3e }

  condition:
    any of them
}