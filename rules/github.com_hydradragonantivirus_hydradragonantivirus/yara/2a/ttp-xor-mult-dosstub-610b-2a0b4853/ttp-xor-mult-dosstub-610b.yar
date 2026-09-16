rule TTP_XOR_MULT_DOSStub_610b {
  strings:
    $key_610b = { 35 63 [2] 41 7b [2] 06 79 [2] 41 68 [2] 0f 64 [2] 03 6e [2] 14 65 [2] 0f 2b [2] 32 }

  condition:
    any of them
}