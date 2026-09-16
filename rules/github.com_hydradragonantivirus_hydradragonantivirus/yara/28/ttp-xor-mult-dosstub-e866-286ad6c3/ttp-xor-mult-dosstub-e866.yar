rule TTP_XOR_MULT_DOSStub_e866 {
  strings:
    $key_e866 = { bc 0e [2] c8 16 [2] 8f 14 [2] c8 05 [2] 86 09 [2] 8a 03 [2] 9d 08 [2] 86 46 [2] bb }

  condition:
    any of them
}