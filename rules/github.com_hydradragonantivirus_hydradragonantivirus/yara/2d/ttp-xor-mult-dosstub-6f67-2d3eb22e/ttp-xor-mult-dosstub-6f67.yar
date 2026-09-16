rule TTP_XOR_MULT_DOSStub_6f67 {
  strings:
    $key_6f67 = { 3b 0f [2] 4f 17 [2] 08 15 [2] 4f 04 [2] 01 08 [2] 0d 02 [2] 1a 09 [2] 01 47 [2] 3c }

  condition:
    any of them
}