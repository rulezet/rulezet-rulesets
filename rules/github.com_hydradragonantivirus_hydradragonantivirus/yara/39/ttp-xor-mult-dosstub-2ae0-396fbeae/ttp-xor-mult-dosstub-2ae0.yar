rule TTP_XOR_MULT_DOSStub_2ae0 {
  strings:
    $key_2ae0 = { 7e 88 [2] 0a 90 [2] 4d 92 [2] 0a 83 [2] 44 8f [2] 48 85 [2] 5f 8e [2] 44 c0 [2] 79 }

  condition:
    any of them
}