rule TTP_XOR_MULT_DOSStub_d866 {
  strings:
    $key_d866 = { 8c 0e [2] f8 16 [2] bf 14 [2] f8 05 [2] b6 09 [2] ba 03 [2] ad 08 [2] b6 46 [2] 8b }

  condition:
    any of them
}