rule TTP_XOR_MULT_DOSStub_1e51 {
  strings:
    $key_1e51 = { 4a 39 [2] 3e 21 [2] 79 23 [2] 3e 32 [2] 70 3e [2] 7c 34 [2] 6b 3f [2] 70 71 [2] 4d }

  condition:
    any of them
}