rule TTP_XOR_MULT_DOSStub_4f21 {
  strings:
    $key_4f21 = { 1b 49 [2] 6f 51 [2] 28 53 [2] 6f 42 [2] 21 4e [2] 2d 44 [2] 3a 4f [2] 21 01 [2] 1c }

  condition:
    any of them
}