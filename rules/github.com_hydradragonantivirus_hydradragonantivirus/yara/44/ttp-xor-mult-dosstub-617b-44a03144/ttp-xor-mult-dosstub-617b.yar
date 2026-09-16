rule TTP_XOR_MULT_DOSStub_617b {
  strings:
    $key_617b = { 35 13 [2] 41 0b [2] 06 09 [2] 41 18 [2] 0f 14 [2] 03 1e [2] 14 15 [2] 0f 5b [2] 32 }

  condition:
    any of them
}