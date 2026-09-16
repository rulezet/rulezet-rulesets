rule TTP_XOR_MULT_DOSStub_d82b {
  strings:
    $key_d82b = { 8c 43 [2] f8 5b [2] bf 59 [2] f8 48 [2] b6 44 [2] ba 4e [2] ad 45 [2] b6 0b [2] 8b }

  condition:
    any of them
}