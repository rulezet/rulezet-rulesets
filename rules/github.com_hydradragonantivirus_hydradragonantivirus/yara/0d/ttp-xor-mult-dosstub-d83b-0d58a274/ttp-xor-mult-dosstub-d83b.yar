rule TTP_XOR_MULT_DOSStub_d83b {
  strings:
    $key_d83b = { 8c 53 [2] f8 4b [2] bf 49 [2] f8 58 [2] b6 54 [2] ba 5e [2] ad 55 [2] b6 1b [2] 8b }

  condition:
    any of them
}