rule TTP_XOR_MULT_DOSStub_6f21 {
  strings:
    $key_6f21 = { 3b 49 [2] 4f 51 [2] 08 53 [2] 4f 42 [2] 01 4e [2] 0d 44 [2] 1a 4f [2] 01 01 [2] 3c }

  condition:
    any of them
}