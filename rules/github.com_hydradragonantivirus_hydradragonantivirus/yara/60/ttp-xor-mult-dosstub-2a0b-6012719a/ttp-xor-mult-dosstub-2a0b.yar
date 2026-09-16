rule TTP_XOR_MULT_DOSStub_2a0b {
  strings:
    $key_2a0b = { 7e 63 [2] 0a 7b [2] 4d 79 [2] 0a 68 [2] 44 64 [2] 48 6e [2] 5f 65 [2] 44 2b [2] 79 }

  condition:
    any of them
}