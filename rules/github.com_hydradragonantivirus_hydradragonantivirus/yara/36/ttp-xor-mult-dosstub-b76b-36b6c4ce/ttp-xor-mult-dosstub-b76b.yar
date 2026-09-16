rule TTP_XOR_MULT_DOSStub_b76b {
  strings:
    $key_b76b = { e3 03 [2] 97 1b [2] d0 19 [2] 97 08 [2] d9 04 [2] d5 0e [2] c2 05 [2] d9 4b [2] e4 }

  condition:
    any of them
}