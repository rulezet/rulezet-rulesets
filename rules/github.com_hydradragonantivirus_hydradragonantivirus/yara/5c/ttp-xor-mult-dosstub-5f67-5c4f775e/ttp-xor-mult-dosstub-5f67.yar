rule TTP_XOR_MULT_DOSStub_5f67 {
  strings:
    $key_5f67 = { 0b 0f [2] 7f 17 [2] 38 15 [2] 7f 04 [2] 31 08 [2] 3d 02 [2] 2a 09 [2] 31 47 [2] 0c }

  condition:
    any of them
}