rule TTP_XOR_MULT_DOSStub_2b0b {
  strings:
    $key_2b0b = { 7f 63 [2] 0b 7b [2] 4c 79 [2] 0b 68 [2] 45 64 [2] 49 6e [2] 5e 65 [2] 45 2b [2] 78 }

  condition:
    any of them
}