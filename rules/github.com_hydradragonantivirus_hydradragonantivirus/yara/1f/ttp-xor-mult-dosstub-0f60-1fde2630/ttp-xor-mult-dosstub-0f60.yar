rule TTP_XOR_MULT_DOSStub_0f60 {
  strings:
    $key_0f60 = { 5b 08 [2] 2f 10 [2] 68 12 [2] 2f 03 [2] 61 0f [2] 6d 05 [2] 7a 0e [2] 61 40 [2] 5c }

  condition:
    any of them
}