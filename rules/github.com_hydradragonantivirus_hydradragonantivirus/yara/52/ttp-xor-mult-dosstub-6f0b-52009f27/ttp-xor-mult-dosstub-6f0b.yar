rule TTP_XOR_MULT_DOSStub_6f0b {
  strings:
    $key_6f0b = { 3b 63 [2] 4f 7b [2] 08 79 [2] 4f 68 [2] 01 64 [2] 0d 6e [2] 1a 65 [2] 01 2b [2] 3c }

  condition:
    any of them
}