rule TTP_XOR_MULT_DOSStub_7e51 {
  strings:
    $key_7e51 = { 2a 39 [2] 5e 21 [2] 19 23 [2] 5e 32 [2] 10 3e [2] 1c 34 [2] 0b 3f [2] 10 71 [2] 2d }

  condition:
    any of them
}