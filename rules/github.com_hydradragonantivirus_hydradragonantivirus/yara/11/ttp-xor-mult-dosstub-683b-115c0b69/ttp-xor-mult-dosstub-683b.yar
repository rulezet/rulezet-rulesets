rule TTP_XOR_MULT_DOSStub_683b {
  strings:
    $key_683b = { 3c 53 [2] 48 4b [2] 0f 49 [2] 48 58 [2] 06 54 [2] 0a 5e [2] 1d 55 [2] 06 1b [2] 3b }

  condition:
    any of them
}