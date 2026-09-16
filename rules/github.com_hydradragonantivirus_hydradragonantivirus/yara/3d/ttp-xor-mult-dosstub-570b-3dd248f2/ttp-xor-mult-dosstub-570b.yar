rule TTP_XOR_MULT_DOSStub_570b {
  strings:
    $key_570b = { 03 63 [2] 77 7b [2] 30 79 [2] 77 68 [2] 39 64 [2] 35 6e [2] 22 65 [2] 39 2b [2] 04 }

  condition:
    any of them
}