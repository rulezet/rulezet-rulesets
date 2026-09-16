rule TTP_XOR_MULT_DOSStub_250b {
  strings:
    $key_250b = { 71 63 [2] 05 7b [2] 42 79 [2] 05 68 [2] 4b 64 [2] 47 6e [2] 50 65 [2] 4b 2b [2] 76 }

  condition:
    any of them
}