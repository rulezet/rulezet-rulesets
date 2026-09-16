rule TTP_XOR_MULT_DOSStub_d826 {
  strings:
    $key_d826 = { 8c 4e [2] f8 56 [2] bf 54 [2] f8 45 [2] b6 49 [2] ba 43 [2] ad 48 [2] b6 06 [2] 8b }

  condition:
    any of them
}