rule TTP_XOR_MULT_DOSStub_0f67 {
  strings:
    $key_0f67 = { 5b 0f [2] 2f 17 [2] 68 15 [2] 2f 04 [2] 61 08 [2] 6d 02 [2] 7a 09 [2] 61 47 [2] 5c }

  condition:
    any of them
}