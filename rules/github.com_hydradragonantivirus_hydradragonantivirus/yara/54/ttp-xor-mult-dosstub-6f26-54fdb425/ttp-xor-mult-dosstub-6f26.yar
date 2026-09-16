rule TTP_XOR_MULT_DOSStub_6f26 {
  strings:
    $key_6f26 = { 3b 4e [2] 4f 56 [2] 08 54 [2] 4f 45 [2] 01 49 [2] 0d 43 [2] 1a 48 [2] 01 06 [2] 3c }

  condition:
    any of them
}