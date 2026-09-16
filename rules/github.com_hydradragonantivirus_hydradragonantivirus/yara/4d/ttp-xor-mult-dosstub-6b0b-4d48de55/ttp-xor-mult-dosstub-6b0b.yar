rule TTP_XOR_MULT_DOSStub_6b0b {
  strings:
    $key_6b0b = { 3f 63 [2] 4b 7b [2] 0c 79 [2] 4b 68 [2] 05 64 [2] 09 6e [2] 1e 65 [2] 05 2b [2] 38 }

  condition:
    any of them
}