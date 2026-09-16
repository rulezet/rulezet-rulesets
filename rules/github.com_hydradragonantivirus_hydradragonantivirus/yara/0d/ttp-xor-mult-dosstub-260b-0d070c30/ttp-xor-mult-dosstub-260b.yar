rule TTP_XOR_MULT_DOSStub_260b {
  strings:
    $key_260b = { 72 63 [2] 06 7b [2] 41 79 [2] 06 68 [2] 48 64 [2] 44 6e [2] 53 65 [2] 48 2b [2] 75 }

  condition:
    any of them
}