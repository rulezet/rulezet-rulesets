rule TTP_XOR_MULT_DOSStub_0f0b {
  strings:
    $key_0f0b = { 5b 63 [2] 2f 7b [2] 68 79 [2] 2f 68 [2] 61 64 [2] 6d 6e [2] 7a 65 [2] 61 2b [2] 5c }

  condition:
    any of them
}