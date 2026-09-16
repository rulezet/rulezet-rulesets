rule TTP_XOR_MULT_DOSStub_5f61 {
  strings:
    $key_5f61 = { 0b 09 [2] 7f 11 [2] 38 13 [2] 7f 02 [2] 31 0e [2] 3d 04 [2] 2a 0f [2] 31 41 [2] 0c }

  condition:
    any of them
}