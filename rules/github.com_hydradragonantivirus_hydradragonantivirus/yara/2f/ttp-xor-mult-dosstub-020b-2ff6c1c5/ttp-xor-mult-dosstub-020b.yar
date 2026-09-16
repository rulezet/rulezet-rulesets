rule TTP_XOR_MULT_DOSStub_020b {
  strings:
    $key_020b = { 56 63 [2] 22 7b [2] 65 79 [2] 22 68 [2] 6c 64 [2] 60 6e [2] 77 65 [2] 6c 2b [2] 51 }

  condition:
    any of them
}