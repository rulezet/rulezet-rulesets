rule TTP_XOR_MULT_DOSStub_4866 {
  strings:
    $key_4866 = { 1c 0e [2] 68 16 [2] 2f 14 [2] 68 05 [2] 26 09 [2] 2a 03 [2] 3d 08 [2] 26 46 [2] 1b }

  condition:
    any of them
}