rule TTP_XOR_MULT_DOSStub_0b67 {
  strings:
    $key_0b67 = { 5f 0f [2] 2b 17 [2] 6c 15 [2] 2b 04 [2] 65 08 [2] 69 02 [2] 7e 09 [2] 65 47 [2] 58 }

  condition:
    any of them
}