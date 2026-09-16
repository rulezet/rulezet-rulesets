rule TTP_XOR_MULT_DOSStub_78cd {
  strings:
    $key_78cd = { 2c a5 [2] 58 bd [2] 1f bf [2] 58 ae [2] 16 a2 [2] 1a a8 [2] 0d a3 [2] 16 ed [2] 2b }

  condition:
    any of them
}