rule TTP_XOR_MULT_DOSStub_054b {
  strings:
    $key_054b = { 51 23 [2] 25 3b [2] 62 39 [2] 25 28 [2] 6b 24 [2] 67 2e [2] 70 25 [2] 6b 6b [2] 56 }

  condition:
    any of them
}