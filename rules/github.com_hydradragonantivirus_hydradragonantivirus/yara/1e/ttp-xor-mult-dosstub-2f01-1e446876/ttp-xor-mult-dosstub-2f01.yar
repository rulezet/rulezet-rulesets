rule TTP_XOR_MULT_DOSStub_2f01 {
  strings:
    $key_2f01 = { 7b 69 [2] 0f 71 [2] 48 73 [2] 0f 62 [2] 41 6e [2] 4d 64 [2] 5a 6f [2] 41 21 [2] 7c }

  condition:
    any of them
}