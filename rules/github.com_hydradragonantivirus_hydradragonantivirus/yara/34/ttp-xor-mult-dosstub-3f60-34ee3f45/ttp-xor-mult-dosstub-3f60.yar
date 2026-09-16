rule TTP_XOR_MULT_DOSStub_3f60 {
  strings:
    $key_3f60 = { 6b 08 [2] 1f 10 [2] 58 12 [2] 1f 03 [2] 51 0f [2] 5d 05 [2] 4a 0e [2] 51 40 [2] 6c }

  condition:
    any of them
}