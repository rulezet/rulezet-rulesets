rule TTP_XOR_MULT_DOSStub_2fe0 {
  strings:
    $key_2fe0 = { 7b 88 [2] 0f 90 [2] 48 92 [2] 0f 83 [2] 41 8f [2] 4d 85 [2] 5a 8e [2] 41 c0 [2] 7c }

  condition:
    any of them
}