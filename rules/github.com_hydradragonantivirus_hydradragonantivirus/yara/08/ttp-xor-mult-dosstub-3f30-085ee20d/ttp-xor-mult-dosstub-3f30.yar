rule TTP_XOR_MULT_DOSStub_3f30 {
  strings:
    $key_3f30 = { 6b 58 [2] 1f 40 [2] 58 42 [2] 1f 53 [2] 51 5f [2] 5d 55 [2] 4a 5e [2] 51 10 [2] 6c }

  condition:
    any of them
}