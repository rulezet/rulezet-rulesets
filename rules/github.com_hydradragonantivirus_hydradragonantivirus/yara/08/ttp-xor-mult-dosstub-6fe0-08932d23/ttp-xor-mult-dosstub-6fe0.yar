rule TTP_XOR_MULT_DOSStub_6fe0 {
  strings:
    $key_6fe0 = { 3b 88 [2] 4f 90 [2] 08 92 [2] 4f 83 [2] 01 8f [2] 0d 85 [2] 1a 8e [2] 01 c0 [2] 3c }

  condition:
    any of them
}