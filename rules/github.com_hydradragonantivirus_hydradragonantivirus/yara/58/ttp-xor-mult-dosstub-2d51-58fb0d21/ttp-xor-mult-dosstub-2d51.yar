rule TTP_XOR_MULT_DOSStub_2d51 {
  strings:
    $key_2d51 = { 79 39 [2] 0d 21 [2] 4a 23 [2] 0d 32 [2] 43 3e [2] 4f 34 [2] 58 3f [2] 43 71 [2] 7e }

  condition:
    any of them
}