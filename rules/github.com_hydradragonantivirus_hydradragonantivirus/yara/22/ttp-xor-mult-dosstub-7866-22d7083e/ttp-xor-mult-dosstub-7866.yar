rule TTP_XOR_MULT_DOSStub_7866 {
  strings:
    $key_7866 = { 2c 0e [2] 58 16 [2] 1f 14 [2] 58 05 [2] 16 09 [2] 1a 03 [2] 0d 08 [2] 16 46 [2] 2b }

  condition:
    any of them
}