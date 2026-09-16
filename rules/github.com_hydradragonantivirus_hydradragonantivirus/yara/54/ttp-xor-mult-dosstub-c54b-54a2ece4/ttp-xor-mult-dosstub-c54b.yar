rule TTP_XOR_MULT_DOSStub_c54b {
  strings:
    $key_c54b = { 91 23 [2] e5 3b [2] a2 39 [2] e5 28 [2] ab 24 [2] a7 2e [2] b0 25 [2] ab 6b [2] 96 }

  condition:
    any of them
}