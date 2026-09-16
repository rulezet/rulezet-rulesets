rule TTP_XOR_MULT_DOSStub_2d67 {
  strings:
    $key_2d67 = { 79 0f [2] 0d 17 [2] 4a 15 [2] 0d 04 [2] 43 08 [2] 4f 02 [2] 58 09 [2] 43 47 [2] 7e }

  condition:
    any of them
}