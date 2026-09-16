rule TTP_XOR_MULT_DOSStub_1866 {
  strings:
    $key_1866 = { 4c 0e [2] 38 16 [2] 7f 14 [2] 38 05 [2] 76 09 [2] 7a 03 [2] 6d 08 [2] 76 46 [2] 4b }

  condition:
    any of them
}