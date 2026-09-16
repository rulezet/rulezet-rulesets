rule TTP_XOR_MULT_DOSStub_6df0 {
  strings:
    $key_6df0 = { 39 98 [2] 4d 80 [2] 0a 82 [2] 4d 93 [2] 03 9f [2] 0f 95 [2] 18 9e [2] 03 d0 [2] 3e }

  condition:
    any of them
}