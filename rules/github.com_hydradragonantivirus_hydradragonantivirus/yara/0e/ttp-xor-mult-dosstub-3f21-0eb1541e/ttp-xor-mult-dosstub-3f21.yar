rule TTP_XOR_MULT_DOSStub_3f21 {
  strings:
    $key_3f21 = { 6b 49 [2] 1f 51 [2] 58 53 [2] 1f 42 [2] 51 4e [2] 5d 44 [2] 4a 4f [2] 51 01 [2] 6c }

  condition:
    any of them
}