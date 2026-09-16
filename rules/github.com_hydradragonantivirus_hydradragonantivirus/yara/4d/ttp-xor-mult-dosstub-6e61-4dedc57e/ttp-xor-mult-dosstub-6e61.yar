rule TTP_XOR_MULT_DOSStub_6e61 {
  strings:
    $key_6e61 = { 3a 09 [2] 4e 11 [2] 09 13 [2] 4e 02 [2] 00 0e [2] 0c 04 [2] 1b 0f [2] 00 41 [2] 3d }

  condition:
    any of them
}