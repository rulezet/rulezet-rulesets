rule TTP_XOR_MULT_DOSStub_2866 {
  strings:
    $key_2866 = { 7c 0e [2] 08 16 [2] 4f 14 [2] 08 05 [2] 46 09 [2] 4a 03 [2] 5d 08 [2] 46 46 [2] 7b }

  condition:
    any of them
}