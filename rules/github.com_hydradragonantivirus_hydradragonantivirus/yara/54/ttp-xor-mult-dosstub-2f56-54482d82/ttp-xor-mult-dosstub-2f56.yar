rule TTP_XOR_MULT_DOSStub_2f56 {
  strings:
    $key_2f56 = { 7b 3e [2] 0f 26 [2] 48 24 [2] 0f 35 [2] 41 39 [2] 4d 33 [2] 5a 38 [2] 41 76 [2] 7c }

  condition:
    any of them
}