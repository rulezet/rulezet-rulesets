rule TTP_XOR_MULT_DOSStub_3f0b {
  strings:
    $key_3f0b = { 6b 63 [2] 1f 7b [2] 58 79 [2] 1f 68 [2] 51 64 [2] 5d 6e [2] 4a 65 [2] 51 2b [2] 6c }

  condition:
    any of them
}