rule TTP_XOR_MULT_DOSStub_0e51 {
  strings:
    $key_0e51 = { 5a 39 [2] 2e 21 [2] 69 23 [2] 2e 32 [2] 60 3e [2] 6c 34 [2] 7b 3f [2] 60 71 [2] 5d }

  condition:
    any of them
}