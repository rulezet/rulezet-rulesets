rule TTP_XOR_MULT_DOSStub_d86b {
  strings:
    $key_d86b = { 8c 03 [2] f8 1b [2] bf 19 [2] f8 08 [2] b6 04 [2] ba 0e [2] ad 05 [2] b6 4b [2] 8b }

  condition:
    any of them
}