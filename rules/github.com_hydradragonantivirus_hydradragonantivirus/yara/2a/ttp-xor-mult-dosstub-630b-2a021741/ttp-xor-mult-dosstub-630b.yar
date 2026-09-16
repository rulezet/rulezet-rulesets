rule TTP_XOR_MULT_DOSStub_630b {
  strings:
    $key_630b = { 37 63 [2] 43 7b [2] 04 79 [2] 43 68 [2] 0d 64 [2] 01 6e [2] 16 65 [2] 0d 2b [2] 30 }

  condition:
    any of them
}