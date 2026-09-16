rule TTP_XOR_MULT_DOSStub_2a61 {
  strings:
    $key_2a61 = { 7e 09 [2] 0a 11 [2] 4d 13 [2] 0a 02 [2] 44 0e [2] 48 04 [2] 5f 0f [2] 44 41 [2] 79 }

  condition:
    any of them
}