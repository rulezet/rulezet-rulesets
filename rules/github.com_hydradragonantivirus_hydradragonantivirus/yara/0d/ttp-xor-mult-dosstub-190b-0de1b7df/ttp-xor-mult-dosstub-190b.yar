rule TTP_XOR_MULT_DOSStub_190b {
  strings:
    $key_190b = { 4d 63 [2] 39 7b [2] 7e 79 [2] 39 68 [2] 77 64 [2] 7b 6e [2] 6c 65 [2] 77 2b [2] 4a }

  condition:
    any of them
}